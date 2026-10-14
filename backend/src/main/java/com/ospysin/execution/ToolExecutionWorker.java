package com.ospysin.execution;

import com.ospysin.execution.sse.SessionSseDomainEvent;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.scope.ScopeAssetRepository;
import com.ospysin.tools.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 3-Phase worker executing inspection tools detached from database transactions with epoch fencing.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ToolExecutionWorker {

    private final ToolExecutionTxService toolExecutionTxService;
    private final ToolCatalogRegistry toolCatalogRegistry;
    private final HostRateLimiter hostRateLimiter;
    private final PolicyEngine policyEngine;
    private final ScopeAssetRepository scopeAssetRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Qualifier("toolExecutionExecutor")
    private final ThreadPoolTaskExecutor toolExecutionExecutor;

    private final AtomicBoolean autoDispatchEnabled = new AtomicBoolean(true);

    public boolean isAutoDispatchEnabled() {
        return autoDispatchEnabled.get();
    }

    public void setAutoDispatchEnabled(boolean enabled) {
        this.autoDispatchEnabled.set(enabled);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onToolExecutionEnqueued(ToolExecutionEnqueuedEvent event) {
        if (autoDispatchEnabled.get()) {
            submitExecution(event.executionId());
        } else {
            log.debug("Auto-dispatch disabled, skipping automatic background dispatch for execution {}", event.executionId());
        }
    }

    public void submitExecution(UUID executionId) {
        log.debug("Submitting execution {} to worker pool", executionId);
        toolExecutionExecutor.execute(() -> executeTask(executionId));
    }

    public void executeTask(UUID executionId) {
        UUID workerId = UUID.randomUUID();
        // Phase 1 (Claim Tx)
        Optional<ClaimedExecution> claimedOpt = toolExecutionTxService.claimExecution(executionId, workerId);
        if (claimedOpt.isEmpty()) {
            log.debug("Execution {} could not be claimed (not PENDING or session not ACTIVE)", executionId);
            return;
        }

        executeClaimed(claimedOpt.get(), workerId);
    }

    /**
     * Claims and executes orphaned PENDING executions across all active sessions using SKIP LOCKED.
     *
     * @return the number of executions claimed and executed
     */
    public int drainPendingQueue() {
        int drained = 0;
        while (true) {
            UUID workerId = UUID.randomUUID();
            Optional<ClaimedExecution> claimedOpt = toolExecutionTxService.claimNextPending(workerId);
            if (claimedOpt.isEmpty()) {
                break;
            }
            drained++;
            executeClaimed(claimedOpt.get(), workerId);
        }
        return drained;
    }

    private void executeClaimed(ClaimedExecution claimed, UUID workerId) {
        log.info("Worker {} starting Phase 2 execution for tool '{}' (execId={}, epoch={})",
                workerId, claimed.toolId(), claimed.executionId(), claimed.claimedEpoch());

        ToolMetadata metadata = toolCatalogRegistry.findMetadata(claimed.toolId()).orElse(null);
        if (metadata == null) {
            toolExecutionTxService.persistFailure(claimed.executionId(), claimed.claimedEpoch(), "UNKNOWN_TOOL", claimed.startedAt());
            return;
        }

        ScopeAsset scopeAsset = scopeAssetRepository.findByEngagementId(claimed.engagementId())
                .stream()
                .findFirst()
                .orElse(null);

        PolicyDecision decision = null;

        // Phase 2: Detached Tool Execution (NO DB Transaction)
        if (metadata.executionType() == ExecutionType.DIRECT_TARGET_PROBE || metadata.executionType() == ExecutionType.THIRD_PARTY_RECON) {
            String targetHost = extractHost(claimed.targetUrl());

            // 1. Rate Limiting (2 req/s per host, 500ms spacing)
            hostRateLimiter.acquire(targetHost);

            // 2. Pre-flight Policy Evaluation
            boolean isSubdomainTakeover = "subdomain_takeover_check".equals(claimed.toolId());
            decision = policyEngine.evaluate(claimed.targetUrl(), claimed.sessionMode(), scopeAsset, isSubdomainTakeover);

            if (!decision.allowed()) {
                log.warn("Policy denied execution {} for target {}: {}", claimed.executionId(), claimed.targetUrl(), decision.reason());
                eventPublisher.publishEvent(new SessionSseDomainEvent(
                        claimed.sessionId(),
                        "policy_alert",
                        Map.of("level", "WARN", "message", decision.reason())
                ));
                toolExecutionTxService.persistFailure(claimed.executionId(), claimed.claimedEpoch(), "POLICY_DENIED", claimed.startedAt(), decision);
                return;
            }
        }

        // 3. Lookup registered OspysinTool bean
        Optional<OspysinTool> toolOpt = toolCatalogRegistry.getTool(claimed.toolId());
        if (toolOpt.isEmpty()) {
            log.warn("Tool '{}' not yet implemented in registry for execution {}", claimed.toolId(), claimed.executionId());
            toolExecutionTxService.persistFailure(claimed.executionId(), claimed.claimedEpoch(), "TOOL_NOT_IMPLEMENTED", claimed.startedAt(), decision);
            return;
        }

        OspysinTool tool = toolOpt.get();
        ToolExecutionContext context = new ToolExecutionContext(
                claimed.sessionId(),
                claimed.executionId(),
                claimed.targetUrl(),
                claimed.sessionMode(),
                scopeAsset,
                claimed.inputParams(),
                decision
        );

        try {
            ToolExecutionOutcome outcome = tool.execute(context);
            // Phase 3 (Fenced Persistence Tx)
            toolExecutionTxService.persistSuccess(claimed.executionId(), claimed.claimedEpoch(), outcome, claimed.startedAt(), decision);
        } catch (Exception ex) {
            log.error("Execution failure for tool '{}' (execId={}): {}", claimed.toolId(), claimed.executionId(), ex.getMessage(), ex);
            String failureReason = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
            toolExecutionTxService.persistFailure(claimed.executionId(), claimed.claimedEpoch(), failureReason, claimed.startedAt(), decision);
        }
    }

    private String extractHost(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return "";
        }
        String trimmed = targetUrl.trim().toLowerCase(Locale.ROOT);
        try {
            if (trimmed.contains("://")) {
                URI uri = URI.create(trimmed);
                if (uri.getHost() != null) {
                    trimmed = uri.getHost().toLowerCase(Locale.ROOT);
                }
            }
        } catch (Exception ignored) {
        }
        int slash = trimmed.indexOf('/');
        if (slash >= 0) {
            trimmed = trimmed.substring(0, slash);
        }
        int lastBracket = trimmed.lastIndexOf(']');
        if (lastBracket >= 0) {
            int colonAfter = trimmed.indexOf(':', lastBracket);
            if (colonAfter > 0) {
                trimmed = trimmed.substring(0, colonAfter);
            }
        } else {
            int firstColon = trimmed.indexOf(':');
            int lastColon = trimmed.lastIndexOf(':');
            if (firstColon >= 0 && firstColon == lastColon) {
                trimmed = trimmed.substring(0, firstColon);
            }
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }
}
