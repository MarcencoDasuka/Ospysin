package com.ospysin.sessions;

import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.engagements.EngagementStatus;
import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.findings.FindingRepository;
import com.ospysin.findings.FindingStatus;
import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.projects.Project;
import com.ospysin.projects.ProjectRepository;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.scope.ScopeAssetRepository;
import com.ospysin.sessions.dto.CreateSessionRequest;
import com.ospysin.sessions.dto.SessionResponse;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import com.ospysin.shared.error.ConflictException;
import com.ospysin.shared.error.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ospysin.execution.sse.SessionSseDomainEvent;
import org.springframework.context.ApplicationEventPublisher;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuditSessionTxService {

    public static final UUID DEFAULT_PROJECT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    private final ProjectRepository projectRepository;
    private final EngagementRepository engagementRepository;
    private final ScopeAssetRepository scopeAssetRepository;
    private final AuditSessionRepository auditSessionRepository;
    private final ToolExecutionRepository toolExecutionRepository;
    private final FindingRepository findingRepository;
    private final AuditEventRepository auditEventRepository;
    private final PolicyEngine policyEngine;
    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    @Transactional
    public SessionResponse initializeSession(CreateSessionRequest request,
                                            PolicyDecision decision,
                                            String statementText,
                                            String statementHash) {
        Instant now = clock.instant();

        // 1. Load pre-seeded Default Project
        Project defaultProject = projectRepository.findById(DEFAULT_PROJECT_ID)
                .orElseThrow(() -> new IllegalStateException("Default project 00000000-0000-0000-0000-000000000001 not found"));

        // 2. Create and persist managed Engagement
        String rawTitle = "Ad-Hoc Audit: " + decision.targetHost();
        String title = rawTitle.length() > 150 ? rawTitle.substring(0, 150) : rawTitle;
        Engagement engagement = Engagement.builder()
                .project(defaultProject)
                .title(title)
                .startDate(LocalDate.now(clock))
                .status(EngagementStatus.ACTIVE)
                .createdAt(now)
                .build();
        engagement = engagementRepository.save(engagement);

        // 3. Determine AssetType and persist bounded ScopeAsset
        AssetType assetType = ObfuscatedIpParser.parse(decision.targetHost()) != null
                ? AssetType.IP
                : AssetType.FQDN;
        ScopeAsset scopeAsset = ScopeAsset.builder()
                .engagement(engagement)
                .assetType(assetType)
                .value(decision.targetHost())
                .isWildcard(false)
                .createdAt(now)
                .build();
        scopeAssetRepository.save(scopeAsset);

        // 4. Create and persist AuditSession
        AuditSession session = AuditSession.builder()
                .engagement(engagement)
                .targetUrl(request.targetUrl().trim())
                .mode(request.mode())
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion(request.scopeAckVersion())
                .scopeAckText(statementText)
                .scopeAckHash(statementHash)
                .scopeAckTimestamp(now)
                .createdAt(now)
                .updatedAt(now)
                .build();
        session = auditSessionRepository.save(session);

        // 5. Record 3 immutable AuditEvent entries:
        // (1) SCOPE_ACKNOWLEDGED
        AuditEvent scopeAckEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.SCOPE_ACKNOWLEDGED)
                .payload(Map.of(
                        "version", request.scopeAckVersion(),
                        "hash", statementHash,
                        "timestamp", now.toString()
                ))
                .timestamp(now)
                .build();
        auditEventRepository.save(scopeAckEvent);

        // (2) POLICY_EVALUATED
        policyEngine.recordAudit(session, decision);

        // (3) SESSION_STARTED
        Map<String, Object> sessionStartedPayload = new HashMap<>();
        sessionStartedPayload.put("targetUrl", session.getTargetUrl());
        sessionStartedPayload.put("mode", session.getMode().name());
        sessionStartedPayload.put("targetHost", decision.targetHost());
        sessionStartedPayload.put("resolvedIp", decision.resolvedIp() != null ? decision.resolvedIp().getHostAddress() : null);

        AuditEvent sessionStartedEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.SESSION_STARTED)
                .payload(sessionStartedPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(sessionStartedEvent);

        return new SessionResponse(
                session.getId(),
                session.getTargetUrl(),
                session.getMode(),
                session.getState(),
                session.isScopeAcknowledged(),
                session.getScopeAckVersion(),
                session.getScopeAckHash(),
                session.getScopeAckTimestamp(),
                0L,
                0L,
                session.getCreatedAt(),
                session.getUpdatedAt()
        );
    }

    @Transactional
    public SessionResponse completeSession(UUID id) {
        AuditSession session = auditSessionRepository.findByIdForUpdate(id)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + id));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Session is already in terminal state: " + session.getState());
        }

        boolean hasActiveExecutions = toolExecutionRepository.existsBySessionIdAndStatusIn(
                id, List.of(ExecutionStatus.PENDING, ExecutionStatus.RUNNING)
        );
        if (hasActiveExecutions) {
            throw new ConflictException("Cannot complete session while tool executions are PENDING or RUNNING");
        }

        Instant now = clock.instant();
        session.setState(SessionState.COMPLETED);
        session.setUpdatedAt(now);
        auditSessionRepository.save(session);

        AuditEvent event = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.SESSION_COMPLETED)
                .payload(Map.of("state", SessionState.COMPLETED.name()))
                .timestamp(now)
                .build();
        auditEventRepository.save(event);

        eventPublisher.publishEvent(new SessionSseDomainEvent(
                session.getId(),
                "session_completed",
                Map.of("sessionId", session.getId().toString())
        ));

        long stepCount = toolExecutionRepository.countBySessionId(id);
        long findingCount = findingRepository.countBySessionIdAndStatusNot(id, FindingStatus.REJECTED);

        return new SessionResponse(
                session.getId(),
                session.getTargetUrl(),
                session.getMode(),
                session.getState(),
                session.isScopeAcknowledged(),
                session.getScopeAckVersion(),
                session.getScopeAckHash(),
                session.getScopeAckTimestamp(),
                stepCount,
                findingCount,
                session.getCreatedAt(),
                session.getUpdatedAt()
        );
    }

    @Transactional
    public SessionResponse abortSession(UUID id) {
        AuditSession session = auditSessionRepository.findByIdForUpdate(id)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + id));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Session is already in terminal state: " + session.getState());
        }

        Instant now = clock.instant();

        List<ToolExecution> pendingOrRunning = toolExecutionRepository.findBySessionIdAndStatusIn(
                id, List.of(ExecutionStatus.PENDING, ExecutionStatus.RUNNING)
        );
        for (ToolExecution execution : pendingOrRunning) {
            execution.setStatus(ExecutionStatus.CANCELLED);
            execution.setEndedAt(now);
            execution.setFailureReason("Session aborted by operator");
            execution.setLeaseEpoch(execution.getLeaseEpoch() + 1);
        }
        if (!pendingOrRunning.isEmpty()) {
            toolExecutionRepository.saveAll(pendingOrRunning);
        }

        session.setState(SessionState.ABORTED);
        session.setUpdatedAt(now);
        auditSessionRepository.save(session);

        AuditEvent event = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.SESSION_ABORTED)
                .payload(Map.of(
                        "state", SessionState.ABORTED.name(),
                        "failureReason", "Session aborted by operator"
                ))
                .timestamp(now)
                .build();
        auditEventRepository.save(event);

        eventPublisher.publishEvent(new SessionSseDomainEvent(
                session.getId(),
                "session_aborted",
                Map.of("sessionId", session.getId().toString())
        ));

        long stepCount = toolExecutionRepository.countBySessionId(id);
        long findingCount = findingRepository.countBySessionIdAndStatusNot(id, FindingStatus.REJECTED);

        return new SessionResponse(
                session.getId(),
                session.getTargetUrl(),
                session.getMode(),
                session.getState(),
                session.isScopeAcknowledged(),
                session.getScopeAckVersion(),
                session.getScopeAckHash(),
                session.getScopeAckTimestamp(),
                stepCount,
                findingCount,
                session.getCreatedAt(),
                session.getUpdatedAt()
        );
    }
}
