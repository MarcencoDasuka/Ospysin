package com.ospysin.llm.service;

import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.execution.sse.SessionSseDomainEvent;
import com.ospysin.llm.dto.*;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Short-lived transactional service handling isolated database reads, audit event writes,
 * and SSE broadcast publishing for LLM advisory workflows.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LlmAdvisoryTxService {

    private final AuditSessionRepository auditSessionRepository;
    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;
    private final ObservationRepository observationRepository;
    private final AuditEventRepository auditEventRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    /**
     * Validates that the session exists and the step belongs to the session (BOLA defense).
     */
    @Transactional(readOnly = true)
    public void validateStepAccess(UUID sessionId, UUID stepId) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Cannot request LLM commentary for session in state: " + session.getState());
        }

        ToolExecution execution = toolExecutionRepository.findById(stepId)
                .orElseThrow(() -> new ResourceNotFoundException("Step not found: " + stepId));

        if (!execution.getSession().getId().equals(sessionId)) {
            throw new ResourceNotFoundException("Step not found: " + stepId);
        }

        if (execution.getStatus() != ExecutionStatus.COMPLETED) {
            throw new ConflictException("Cannot generate LLM commentary for step in status: " + execution.getStatus());
        }
    }

    /**
     * Validates that the session exists and is ACTIVE.
     */
    @Transactional(readOnly = true)
    public void validateChatAccess(UUID sessionId) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Cannot initiate chat on session in state: " + session.getState());
        }
    }

    /**
     * Loads context for Comment Mode, records LLM_QUERY audit event, and returns a detached snapshot.
     */
    @Transactional
    public CommentContextSnapshot loadStepContextAndRecordQuery(UUID sessionId, UUID stepId) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Cannot request LLM commentary for session in state: " + session.getState());
        }

        ToolExecution execution = toolExecutionRepository.findById(stepId)
                .orElseThrow(() -> new ResourceNotFoundException("Step not found: " + stepId));

        if (!execution.getSession().getId().equals(sessionId)) {
            throw new ResourceNotFoundException("Step not found: " + stepId);
        }

        if (execution.getStatus() != ExecutionStatus.COMPLETED) {
            throw new ConflictException("Cannot generate LLM commentary for step in status: " + execution.getStatus());
        }

        // 1. Load and group all observations for this session to eliminate N+1 queries
        List<Observation> allObservations = observationRepository.findBySessionIdOrderByDetectedAtAsc(sessionId);
        Map<UUID, List<String>> obsByExecId = new HashMap<>();
        for (Observation o : allObservations) {
            if (o.getResult() != null && o.getResult().getExecution() != null) {
                UUID execId = o.getResult().getExecution().getId();
                obsByExecId.computeIfAbsent(execId, k -> new ArrayList<>())
                        .add(o.getSeverityHeuristic() + ": " + o.getDescription());
            }
        }

        // 2. Load completed steps summary
        List<ToolExecution> allExecutions = toolExecutionRepository.findBySessionIdOrderByCreatedAtAsc(sessionId);
        List<CompletedStepSummary> completedStepSummaries = new ArrayList<>();

        for (ToolExecution exec : allExecutions) {
            if (exec.getStatus() == ExecutionStatus.COMPLETED) {
                List<String> obsDescriptions = obsByExecId.getOrDefault(exec.getId(), Collections.emptyList());
                completedStepSummaries.add(new CompletedStepSummary(
                        exec.getId(),
                        exec.getToolId(),
                        exec.getEndedAt(),
                        obsDescriptions
                ));
            }
        }

        SessionContextSnapshot sessionSnapshot = new SessionContextSnapshot(
                session.getId(),
                session.getTargetUrl(),
                session.getMode(),
                completedStepSummaries
        );

        // 3. Load active step details
        Optional<ToolResult> resultOpt = toolResultRepository.findByExecutionId(stepId);
        Map<String, Object> parsedData = resultOpt.map(ToolResult::getParsedData).orElse(Collections.emptyMap());
        String rawOutput = resultOpt.map(ToolResult::getRawOutput).orElse(null);
        List<String> activeObs = obsByExecId.getOrDefault(stepId, Collections.emptyList());

        StepContextSnapshot stepSnapshot = new StepContextSnapshot(
                execution.getId(),
                execution.getToolId(),
                execution.getInputParams(),
                parsedData,
                rawOutput,
                activeObs
        );

        // 4. Record AuditEventType.LLM_QUERY
        Instant now = clock.instant();
        Map<String, Object> queryPayload = new HashMap<>();
        queryPayload.put("sessionId", sessionId.toString());
        queryPayload.put("stepId", stepId.toString());
        queryPayload.put("toolId", execution.getToolId());
        queryPayload.put("mode", "COMMENT");

        AuditEvent auditEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.LLM_QUERY)
                .payload(queryPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        return new CommentContextSnapshot(sessionSnapshot, stepSnapshot);
    }

    /**
     * Loads context for Chat Mode, records LLM_QUERY audit event, and returns a detached snapshot.
     */
    @Transactional
    public SessionContextSnapshot loadChatContextAndRecordQuery(UUID sessionId, String userMessage) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            throw new ConflictException("Cannot initiate chat on session in state: " + session.getState());
        }

        // Load and group all observations for this session to eliminate N+1 queries
        List<Observation> allObservations = observationRepository.findBySessionIdOrderByDetectedAtAsc(sessionId);
        Map<UUID, List<String>> obsByExecId = new HashMap<>();
        for (Observation o : allObservations) {
            if (o.getResult() != null && o.getResult().getExecution() != null) {
                UUID execId = o.getResult().getExecution().getId();
                obsByExecId.computeIfAbsent(execId, k -> new ArrayList<>())
                        .add(o.getSeverityHeuristic() + ": " + o.getDescription());
            }
        }

        List<ToolExecution> allExecutions = toolExecutionRepository.findBySessionIdOrderByCreatedAtAsc(sessionId);
        List<CompletedStepSummary> completedStepSummaries = new ArrayList<>();

        for (ToolExecution exec : allExecutions) {
            if (exec.getStatus() == ExecutionStatus.COMPLETED) {
                List<String> obsDescriptions = obsByExecId.getOrDefault(exec.getId(), Collections.emptyList());
                completedStepSummaries.add(new CompletedStepSummary(
                        exec.getId(),
                        exec.getToolId(),
                        exec.getEndedAt(),
                        obsDescriptions
                ));
            }
        }

        SessionContextSnapshot sessionSnapshot = new SessionContextSnapshot(
                session.getId(),
                session.getTargetUrl(),
                session.getMode(),
                completedStepSummaries
        );

        Instant now = clock.instant();
        Map<String, Object> queryPayload = new HashMap<>();
        queryPayload.put("sessionId", sessionId.toString());
        queryPayload.put("userMessage", userMessage);
        queryPayload.put("mode", "CHAT");

        AuditEvent auditEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.LLM_QUERY)
                .payload(queryPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        return sessionSnapshot;
    }

    /**
     * Records LLM_COMMENT audit event and broadcasts llm_comment_ready SSE event.
     */
    @Transactional
    public void recordCommentAndBroadcast(UUID sessionId, LlmCommentPayload payload) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            log.warn("Fencing late LLM advisory output for non-active session {} (state={})", sessionId, session.getState());
            return;
        }

        Instant now = payload.timestamp() != null ? payload.timestamp() : clock.instant();

        Map<String, Object> auditPayload = new HashMap<>();
        auditPayload.put("stepId", payload.stepId().toString());
        auditPayload.put("toolId", payload.toolId() != null ? payload.toolId() : "");
        auditPayload.put("comment", payload.comment());
        auditPayload.put("suggestedTool", payload.suggestedTool());
        auditPayload.put("suggestedReason", payload.suggestedReason());
        auditPayload.put("timestamp", now.toString());

        AuditEvent auditEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.LLM_COMMENT)
                .payload(auditPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        Map<String, Object> sseData = new HashMap<>();
        sseData.put("stepId", payload.stepId().toString());
        sseData.put("toolId", payload.toolId() != null ? payload.toolId() : "");
        sseData.put("comment", payload.comment());
        sseData.put("suggestedTool", payload.suggestedTool());
        sseData.put("suggestedReason", payload.suggestedReason());
        sseData.put("timestamp", now.toString());

        eventPublisher.publishEvent(new SessionSseDomainEvent(session.getId(), "llm_comment_ready", sseData));
        log.info("Recorded LLM_COMMENT and published llm_comment_ready for session {} and step {}", sessionId, payload.stepId());
    }

    /**
     * Records LLM_COMMENT audit event and broadcasts llm_chat_reply SSE event.
     */
    @Transactional
    public void recordChatReplyAndBroadcast(UUID sessionId, LlmChatReplyPayload payload) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() != SessionState.ACTIVE) {
            log.warn("Fencing late LLM advisory output for non-active session {} (state={})", sessionId, session.getState());
            return;
        }

        Instant now = payload.timestamp() != null ? payload.timestamp() : clock.instant();

        Map<String, Object> auditPayload = new HashMap<>();
        auditPayload.put("reply", payload.reply());
        auditPayload.put("timestamp", now.toString());

        AuditEvent auditEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.LLM_COMMENT)
                .payload(auditPayload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        Map<String, Object> sseData = new HashMap<>();
        sseData.put("reply", payload.reply());
        sseData.put("timestamp", now.toString());

        eventPublisher.publishEvent(new SessionSseDomainEvent(session.getId(), "llm_chat_reply", sseData));
        log.info("Recorded LLM_COMMENT and published llm_chat_reply for session {}", sessionId);
    }
}
