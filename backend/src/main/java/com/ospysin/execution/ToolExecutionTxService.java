package com.ospysin.execution;

import com.ospysin.execution.dto.ObservationDto;
import com.ospysin.execution.dto.StepDetailResponse;
import com.ospysin.execution.dto.StepSummaryResponse;
import com.ospysin.execution.sse.SessionSseDomainEvent;
import com.ospysin.observations.Observation;
import com.ospysin.observations.ObservationRepository;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.sessions.SessionState;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import com.ospysin.shared.error.ConflictException;
import com.ospysin.shared.error.ResourceNotFoundException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionOutcome;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Transactional boundary coordinating Phase 1 Enqueue, Phase 1 Claim, Phase 3 Persistence,
 * lease reclamation watchdog, and Step queries.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ToolExecutionTxService {

    private final AuditSessionRepository auditSessionRepository;
    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;
    private final ObservationRepository observationRepository;
    private final AuditEventRepository auditEventRepository;
    private final PolicyEngine policyEngine;
    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    /**
     * Phase 1 (Ingestion): Enqueues a ToolExecution with status PENDING under session row lock.
     */
    @Transactional
    public ToolExecution enqueueExecution(UUID sessionId, String toolId, Map<String, Object> params) {
        AuditSession session = auditSessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Cannot enqueue tool execution for session in state: " + session.getState());
        }

        // Duplicate / Concurrency Guard: at most 1 active (PENDING or RUNNING) execution per session
        boolean hasActive = toolExecutionRepository.existsBySessionIdAndStatusIn(
                sessionId,
                List.of(ExecutionStatus.PENDING, ExecutionStatus.RUNNING)
        );
        if (hasActive) {
            throw new ConflictException("An active tool execution is already PENDING or RUNNING for session " + sessionId);
        }

        Instant now = clock.instant();
        ToolExecution execution = ToolExecution.builder()
                .session(session)
                .toolId(toolId)
                .status(ExecutionStatus.PENDING)
                .inputParams(params)
                .leaseOwner(null)
                .leaseEpoch(0)
                .attempts(0)
                .createdAt(now)
                .build();
        execution = toolExecutionRepository.save(execution);

        Map<String, Object> auditPayload = new HashMap<>();
        auditPayload.put("executionId", execution.getId().toString());
        auditPayload.put("toolId", toolId);
        auditPayload.put("status", ExecutionStatus.PENDING.name());
        auditPayload.put("inputParams", params != null ? params : Map.of());

        AuditEvent auditEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.TOOL_TRIGGERED)
                .payload(auditPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        Map<String, Object> sseData = Map.of(
                "executionId", execution.getId().toString(),
                "toolId", toolId,
                "status", ExecutionStatus.PENDING.name()
        );
        eventPublisher.publishEvent(new SessionSseDomainEvent(session.getId(), "step_queued", sseData));
        eventPublisher.publishEvent(new ToolExecutionEnqueuedEvent(execution.getId()));

        return execution;
    }

    /**
     * Phase 1 (Claim Tx): Claims a PENDING execution, increments lease_epoch, transitions to RUNNING.
     * Enforces strict global row lock ordering: AuditSession -> ToolExecution to prevent AB-BA deadlocks.
     */
    @Transactional
    public Optional<ClaimedExecution> claimExecution(UUID executionId, UUID workerId) {
        // 1. Read execution without lock first to discover its parent session
        Optional<ToolExecution> uncommittedOpt = toolExecutionRepository.findById(executionId);
        if (uncommittedOpt.isEmpty()) {
            return Optional.empty();
        }

        UUID sessionId = uncommittedOpt.get().getSession().getId();

        // 2. Strict lock hierarchy: Always acquire AuditSession row lock FIRST
        AuditSession session = auditSessionRepository.findByIdForUpdate(sessionId).orElse(null);
        if (session == null || session.getState() != SessionState.ACTIVE) {
            return Optional.empty();
        }

        // Concurrency guard: verify no other execution is RUNNING in this session
        boolean otherRunning = toolExecutionRepository.existsBySessionIdAndStatusIn(
                session.getId(),
                List.of(ExecutionStatus.RUNNING)
        );
        if (otherRunning) {
            log.debug("Session {} already has a RUNNING execution. Deferring execution {}", session.getId(), executionId);
            return Optional.empty();
        }

        // 3. Acquire ToolExecution row lock SECOND
        Optional<ToolExecution> execOpt = toolExecutionRepository.findByIdForUpdate(executionId);
        if (execOpt.isEmpty()) {
            return Optional.empty();
        }

        ToolExecution execution = execOpt.get();
        if (execution.getStatus() != ExecutionStatus.PENDING) {
            return Optional.empty();
        }

        Instant now = clock.instant();
        int nextEpoch = execution.getLeaseEpoch() + 1;
        execution.setLeaseEpoch(nextEpoch);
        execution.setAttempts(execution.getAttempts() + 1);
        execution.setStatus(ExecutionStatus.RUNNING);
        execution.setLeaseOwner(workerId);
        execution.setStartedAt(now);
        execution.setLeaseExpiresAt(now.plusSeconds(35));
        toolExecutionRepository.save(execution);

        Map<String, Object> sseData = Map.of(
                "executionId", execution.getId().toString(),
                "toolId", execution.getToolId(),
                "status", ExecutionStatus.RUNNING.name(),
                "startedAt", now.toString()
        );
        eventPublisher.publishEvent(new SessionSseDomainEvent(session.getId(), "step_started", sseData));

        return Optional.of(new ClaimedExecution(
                execution.getId(),
                session.getId(),
                session.getEngagement().getId(),
                execution.getToolId(),
                nextEpoch,
                execution.getInputParams(),
                session.getTargetUrl(),
                session.getMode(),
                now
        ));
    }

    /**
     * Claims the oldest claimable PENDING execution where no other execution is RUNNING in the session.
     * Selects candidate execution IDs without locking, and acquires row locks in strict
     * global order (AuditSession -> ToolExecution) via claimExecution().
     */
    @Transactional
    public Optional<ClaimedExecution> claimNextPending(UUID workerId) {
        List<UUID> candidateIds = toolExecutionRepository.findPendingCandidateIds(PageRequest.of(0, 10));
        for (UUID candidateId : candidateIds) {
            Optional<ClaimedExecution> claimedOpt = claimExecution(candidateId, workerId);
            if (claimedOpt.isPresent()) {
                return claimedOpt;
            }
        }
        return Optional.empty();
    }

    /**
     * Phase 3 (Fenced Persistence Tx): Validates lease_epoch and session state, persists ToolResult and Observations.
     * Records POLICY_EVALUATED forensic audit event if policy was evaluated during Phase 2.
     */
    @Transactional
    public boolean persistSuccess(UUID executionId, int claimedEpoch, ToolExecutionOutcome outcome, Instant startedAt, PolicyDecision policyDecision) {
        Optional<ToolExecution> execOpt = toolExecutionRepository.findByIdForUpdate(executionId);
        if (execOpt.isEmpty()) {
            log.warn("Execution {} not found for Phase 3 persistence", executionId);
            return false;
        }

        ToolExecution execution = execOpt.get();
        if (execution.getStatus() != ExecutionStatus.RUNNING
                || execution.getLeaseEpoch() != claimedEpoch
                || execution.getSession().getState() != SessionState.ACTIVE) {
            log.warn("Fencing rejected stale persistSuccess for execution {}: status={}, epoch={}, claimedEpoch={}, sessionState={}",
                    executionId, execution.getStatus(), execution.getLeaseEpoch(), claimedEpoch, execution.getSession().getState());
            return false;
        }

        Instant now = clock.instant();
        long durationMs = startedAt != null ? Duration.between(startedAt, now).toMillis() : 0L;
        execution.setStatus(ExecutionStatus.COMPLETED);
        execution.setEndedAt(now);
        execution.setDurationMs(durationMs);
        toolExecutionRepository.save(execution);

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput(outcome.rawOutput())
                .parsedData(outcome.parsedData())
                .score(outcome.score())
                .hasErrors(outcome.hasErrors())
                .createdAt(now)
                .build();
        result = toolResultRepository.save(result);

        int obsCount = 0;
        if (outcome.observations() != null && !outcome.observations().isEmpty()) {
            List<Observation> observations = new ArrayList<>();
            for (ObservationDraft draft : outcome.observations()) {
                Observation obs = Observation.builder()
                        .result(result)
                        .category(draft.category())
                        .description(draft.description())
                        .severityHeuristic(draft.severityHeuristic())
                        .detectedAt(now)
                        .build();
                observations.add(obs);
            }
            observationRepository.saveAll(observations);
            obsCount = observations.size();
        }

        // Record forensic POLICY_EVALUATED event if policy was evaluated
        if (policyDecision != null) {
            policyEngine.recordAudit(execution.getSession(), policyDecision);
        }

        Map<String, Object> auditPayload = new HashMap<>();
        auditPayload.put("executionId", executionId.toString());
        auditPayload.put("toolId", execution.getToolId());
        auditPayload.put("status", ExecutionStatus.COMPLETED.name());
        auditPayload.put("durationMs", durationMs);
        auditPayload.put("observationCount", obsCount);

        AuditEvent auditEvent = AuditEvent.builder()
                .session(execution.getSession())
                .eventType(AuditEventType.TOOL_FINISHED)
                .payload(auditPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        Map<String, Object> sseData = Map.of(
                "executionId", executionId.toString(),
                "toolId", execution.getToolId(),
                "status", ExecutionStatus.COMPLETED.name(),
                "durationMs", durationMs,
                "observationCount", obsCount
        );
        eventPublisher.publishEvent(new SessionSseDomainEvent(execution.getSession().getId(), "step_finished", sseData));

        return true;
    }

    @Transactional
    public boolean persistSuccess(UUID executionId, int claimedEpoch, ToolExecutionOutcome outcome, Instant startedAt) {
        return persistSuccess(executionId, claimedEpoch, outcome, startedAt, null);
    }

    /**
     * Phase 3 (Fenced Failure Tx): Validates lease_epoch and session state, transitions to FAILED with failureReason.
     * Records POLICY_EVALUATED forensic audit event if policy was evaluated during Phase 2.
     */
    @Transactional
    public boolean persistFailure(UUID executionId, int claimedEpoch, String failureReason, Instant startedAt, PolicyDecision policyDecision) {
        Optional<ToolExecution> execOpt = toolExecutionRepository.findByIdForUpdate(executionId);
        if (execOpt.isEmpty()) {
            return false;
        }

        ToolExecution execution = execOpt.get();
        if (execution.getStatus() != ExecutionStatus.RUNNING
                || execution.getLeaseEpoch() != claimedEpoch
                || execution.getSession().getState() != SessionState.ACTIVE) {
            log.warn("Fencing rejected stale persistFailure for execution {}: status={}, epoch={}, claimedEpoch={}, sessionState={}",
                    executionId, execution.getStatus(), execution.getLeaseEpoch(), claimedEpoch, execution.getSession().getState());
            return false;
        }

        Instant now = clock.instant();
        long durationMs = startedAt != null ? Duration.between(startedAt, now).toMillis() : 0L;
        execution.setStatus(ExecutionStatus.FAILED);
        execution.setEndedAt(now);
        execution.setDurationMs(durationMs);
        String truncatedReason = failureReason != null && failureReason.length() > 100
                ? failureReason.substring(0, 100)
                : failureReason;
        execution.setFailureReason(truncatedReason);
        toolExecutionRepository.save(execution);

        // Record forensic POLICY_EVALUATED event if policy was evaluated
        if (policyDecision != null) {
            policyEngine.recordAudit(execution.getSession(), policyDecision);
        }

        Map<String, Object> auditPayload = new HashMap<>();
        auditPayload.put("executionId", executionId.toString());
        auditPayload.put("toolId", execution.getToolId());
        auditPayload.put("status", ExecutionStatus.FAILED.name());
        auditPayload.put("durationMs", durationMs);
        auditPayload.put("failureReason", truncatedReason);

        AuditEvent auditEvent = AuditEvent.builder()
                .session(execution.getSession())
                .eventType(AuditEventType.TOOL_FINISHED)
                .payload(auditPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        Map<String, Object> sseData = Map.of(
                "executionId", executionId.toString(),
                "status", ExecutionStatus.FAILED.name(),
                "failureReason", truncatedReason != null ? truncatedReason : ""
        );
        eventPublisher.publishEvent(new SessionSseDomainEvent(execution.getSession().getId(), "step_failed", sseData));

        return true;
    }

    @Transactional
    public boolean persistFailure(UUID executionId, int claimedEpoch, String failureReason, Instant startedAt) {
        return persistFailure(executionId, claimedEpoch, failureReason, startedAt, null);
    }

    /**
     * Reclaims expired leases for executions in RUNNING state whose leaseExpiresAt has elapsed.
     */
    @Transactional
    public int reclaimExpiredLeases() {
        Instant now = clock.instant();
        List<ToolExecution> expired = toolExecutionRepository.findExpiredLeasesForUpdate(ExecutionStatus.RUNNING, now);
        if (expired.isEmpty()) {
            return 0;
        }

        for (ToolExecution execution : expired) {
            int newEpoch = execution.getLeaseEpoch() + 1;
            execution.setLeaseEpoch(newEpoch);
            execution.setStatus(ExecutionStatus.FAILED);
            execution.setEndedAt(now);
            execution.setFailureReason("LEASE_EXPIRED");
            toolExecutionRepository.save(execution);

            AuditEvent auditEvent = AuditEvent.builder()
                    .session(execution.getSession())
                    .eventType(AuditEventType.TOOL_FINISHED)
                    .payload(Map.of(
                            "executionId", execution.getId().toString(),
                            "toolId", execution.getToolId(),
                            "status", ExecutionStatus.FAILED.name(),
                            "failureReason", "LEASE_EXPIRED"
                    ))
                    .timestamp(now)
                    .build();
            auditEventRepository.save(auditEvent);

            Map<String, Object> sseData = Map.of(
                    "executionId", execution.getId().toString(),
                    "status", ExecutionStatus.FAILED.name(),
                    "failureReason", "LEASE_EXPIRED"
            );
            eventPublisher.publishEvent(new SessionSseDomainEvent(execution.getSession().getId(), "step_failed", sseData));
            log.warn("Reclaimed expired lease for execution {} (session {})", execution.getId(), execution.getSession().getId());
        }
        return expired.size();
    }

    /**
     * Lists all tool steps for sessionId ordered by createdAt ASC using batch observation counts.
     */
    @Transactional(readOnly = true)
    public List<StepSummaryResponse> getSteps(UUID sessionId) {
        if (!auditSessionRepository.existsById(sessionId)) {
            throw new ResourceNotFoundException("Session not found: " + sessionId);
        }

        List<ToolExecution> executions = toolExecutionRepository.findBySessionIdOrderByCreatedAtAsc(sessionId);
        if (executions.isEmpty()) {
            return Collections.emptyList();
        }

        List<UUID> execIds = executions.stream().map(ToolExecution::getId).toList();
        Map<UUID, Long> obsCounts = new HashMap<>();
        List<Object[]> countRows = observationRepository.countObservationsByExecutionIds(execIds);
        for (Object[] row : countRows) {
            obsCounts.put((UUID) row[0], (Long) row[1]);
        }

        return executions.stream()
                .map(e -> new StepSummaryResponse(
                        e.getId(),
                        e.getToolId(),
                        e.getStatus(),
                        e.getDurationMs(),
                        obsCounts.getOrDefault(e.getId(), 0L),
                        e.getStartedAt(),
                        e.getEndedAt()
                ))
                .toList();
    }

    /**
     * Fetches detailed step execution including ToolResult and Observations.
     * Enforces object-level authorization (BOLA) ensuring execution belongs to sessionId.
     */
    @Transactional(readOnly = true)
    public StepDetailResponse getStepDetail(UUID sessionId, UUID stepId) {
        if (!auditSessionRepository.existsById(sessionId)) {
            throw new ResourceNotFoundException("Session not found: " + sessionId);
        }

        ToolExecution execution = toolExecutionRepository.findById(stepId)
                .orElseThrow(() -> new ResourceNotFoundException("Step not found: " + stepId));

        // BOLA Object-Level Access Control Guard
        if (!execution.getSession().getId().equals(sessionId)) {
            throw new ResourceNotFoundException("Step not found: " + stepId);
        }

        Optional<ToolResult> resultOpt = toolResultRepository.findByExecutionId(stepId);
        String rawOutput = resultOpt.map(ToolResult::getRawOutput).orElse(null);
        Map<String, Object> parsedData = resultOpt.map(ToolResult::getParsedData).orElse(Collections.emptyMap());
        Integer score = resultOpt.map(ToolResult::getScore).orElse(null);

        List<ObservationDto> observations = Collections.emptyList();
        if (resultOpt.isPresent()) {
            observations = observationRepository.findByResultId(resultOpt.get().getId()).stream()
                    .map(obs -> new ObservationDto(
                            obs.getId(),
                            obs.getCategory(),
                            obs.getDescription(),
                            obs.getSeverityHeuristic(),
                            obs.getDetectedAt()
                    ))
                    .toList();
        }

        UUID resultId = resultOpt.map(ToolResult::getId).orElse(null);

        return new StepDetailResponse(
                execution.getId(),
                resultId,
                execution.getToolId(),
                execution.getStatus(),
                execution.getDurationMs(),
                execution.getFailureReason(),
                rawOutput,
                parsedData,
                score,
                observations,
                execution.getStartedAt(),
                execution.getEndedAt()
        );
    }
}
