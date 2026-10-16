package com.ospysin.findings;

import com.ospysin.evidence.Evidence;
import com.ospysin.evidence.EvidenceRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.findings.dto.*;
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
import com.ospysin.shared.error.ValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class FindingTxService {

    private final FindingRepository findingRepository;
    private final EvidenceRepository evidenceRepository;
    private final ObservationRepository observationRepository;
    private final ToolResultRepository toolResultRepository;
    private final AuditSessionRepository auditSessionRepository;
    private final AuditEventRepository auditEventRepository;
    private final Clock clock;

    /**
     * Retrieves all automated observations for an audit session.
     */
    @Transactional(readOnly = true)
    public List<SessionObservationResponse> getSessionObservations(UUID sessionId) {
        if (!auditSessionRepository.existsById(sessionId)) {
            throw new ResourceNotFoundException("Session not found: " + sessionId);
        }

        List<Observation> observations = observationRepository.findBySessionIdOrderByDetectedAtAsc(sessionId);
        return observations.stream()
                .map(obs -> new SessionObservationResponse(
                        obs.getId(),
                        obs.getResult().getExecution().getId(),
                        obs.getResult().getId(),
                        obs.getResult().getExecution().getToolId(),
                        obs.getCategory(),
                        obs.getDescription(),
                        obs.getSeverityHeuristic(),
                        obs.getDetectedAt()
                ))
                .toList();
    }

    /**
     * Retrieves all findings for a session with batch-loaded evidence (zero N+1 queries).
     */
    @Transactional(readOnly = true)
    public List<FindingResponse> getFindings(UUID sessionId) {
        if (!auditSessionRepository.existsById(sessionId)) {
            throw new ResourceNotFoundException("Session not found: " + sessionId);
        }

        List<Finding> findings = findingRepository.findBySessionIdOrderByCreatedAtAsc(sessionId);
        if (findings.isEmpty()) {
            return Collections.emptyList();
        }

        List<UUID> findingIds = findings.stream().map(Finding::getId).toList();
        List<Evidence> allEvidence = evidenceRepository.findByFindingIdInOrderByCreatedAtAsc(findingIds);

        Map<UUID, List<EvidenceResponse>> evidenceByFinding = allEvidence.stream()
                .map(e -> new EvidenceResponse(
                        e.getId(),
                        e.getFinding().getId(),
                        e.getResult().getId(),
                        e.getResult().getExecution().getId(),
                        e.getResult().getExecution().getToolId(),
                        e.getSnippet(),
                        e.getCreatedAt()
                ))
                .collect(Collectors.groupingBy(EvidenceResponse::findingId));

        return findings.stream()
                .map(f -> new FindingResponse(
                        f.getId(),
                        f.getSession().getId(),
                        f.getObservation() != null ? f.getObservation().getId() : null,
                        f.getTitle(),
                        f.getDescription(),
                        f.getSeverity(),
                        f.getConfidence(),
                        f.getStatus(),
                        f.getRejectionReason(),
                        f.getRemediation(),
                        evidenceByFinding.getOrDefault(f.getId(), Collections.emptyList()),
                        f.getCreatedAt(),
                        f.getUpdatedAt()
                ))
                .toList();
    }

    /**
     * Creates a new finding for an active or completed session.
     */
    @Transactional
    public FindingResponse createFinding(UUID sessionId, CreateFindingRequest request) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() == SessionState.ABORTED) {
            throw new ConflictException("Cannot create findings for an ABORTED session");
        }

        Observation observation = null;
        if (request.observationId() != null) {
            observation = observationRepository.findById(request.observationId())
                    .orElseThrow(() -> new ResourceNotFoundException("Observation not found: " + request.observationId()));

            // BOLA / Cross-Session Guard
            if (!observation.getResult().getExecution().getSession().getId().equals(sessionId)) {
                throw new ResourceNotFoundException("Observation not found in session: " + request.observationId());
            }
        }

        FindingConfidence resolvedConfidence = request.confidence();
        if (resolvedConfidence == null) {
            resolvedConfidence = (request.observationId() != null)
                    ? FindingConfidence.FIRM
                    : FindingConfidence.TENTATIVE;
        }

        Instant now = clock.instant();
        String remediation = (request.remediation() != null && !request.remediation().isBlank())
                ? request.remediation().trim()
                : null;

        Finding finding = Finding.builder()
                .session(session)
                .observation(observation)
                .title(request.title().trim())
                .description(request.description().trim())
                .severity(request.severity())
                .confidence(resolvedConfidence)
                .status(FindingStatus.OPEN)
                .remediation(remediation)
                .createdAt(now)
                .updatedAt(now)
                .build();

        finding = findingRepository.save(finding);

        Map<String, Object> payload = new HashMap<>();
        payload.put("findingId", finding.getId().toString());
        payload.put("title", finding.getTitle());
        payload.put("severity", finding.getSeverity().name());
        payload.put("confidence", finding.getConfidence().name());
        payload.put("status", finding.getStatus().name());
        if (observation != null) {
            payload.put("observationId", observation.getId().toString());
        }

        AuditEvent auditEvent = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.FINDING_CREATED)
                .payload(payload)
                .timestamp(now)
                .build();
        auditEventRepository.save(auditEvent);

        return new FindingResponse(
                finding.getId(),
                session.getId(),
                observation != null ? observation.getId() : null,
                finding.getTitle(),
                finding.getDescription(),
                finding.getSeverity(),
                finding.getConfidence(),
                finding.getStatus(),
                finding.getRejectionReason(),
                finding.getRemediation(),
                Collections.emptyList(),
                finding.getCreatedAt(),
                finding.getUpdatedAt()
        );
    }

    /**
     * Updates an existing finding, enforcing the domain state machine and BOLA guards.
     */
    @Transactional
    public FindingResponse updateFinding(UUID sessionId, UUID findingId, UpdateFindingRequest request) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        Finding finding = findingRepository.findByIdAndSessionId(findingId, sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding not found: " + findingId));

        if (session.getState() == SessionState.ABORTED) {
            throw new ConflictException("Cannot modify findings in an ABORTED session");
        }

        FindingStatus currentStatus = finding.getStatus();
        if (currentStatus == FindingStatus.REJECTED || currentStatus == FindingStatus.FALSE_POSITIVE) {
            throw new ConflictException("Cannot transition or modify finding in terminal state: " + currentStatus);
        }

        FindingStatus targetStatus = request.status();
        if (targetStatus != null && targetStatus != currentStatus) {
            boolean allowed = (currentStatus == FindingStatus.OPEN && (
                    targetStatus == FindingStatus.CONFIRMED ||
                    targetStatus == FindingStatus.FALSE_POSITIVE ||
                    targetStatus == FindingStatus.REJECTED
            )) || (currentStatus == FindingStatus.CONFIRMED && targetStatus == FindingStatus.REJECTED);

            if (!allowed) {
                throw new ConflictException("Invalid finding status transition from " + currentStatus + " to " + targetStatus);
            }
        }

        if (targetStatus == FindingStatus.REJECTED) {
            if (request.rejectionReason() == null || request.rejectionReason().trim().isEmpty()) {
                throw new ValidationException(
                        "Rejection reason is required when status is REJECTED",
                        List.of(new com.ospysin.shared.error.InvalidParam("rejectionReason", "Rejection reason is required when status is REJECTED"))
                );
            }
            finding.setRejectionReason(request.rejectionReason().trim());
        }

        if (request.title() != null) {
            if (request.title().isBlank()) {
                throw new ValidationException(
                        "Title cannot be blank",
                        List.of(new com.ospysin.shared.error.InvalidParam("title", "Title cannot be blank"))
                );
            }
            finding.setTitle(request.title().trim());
        }

        if (request.description() != null) {
            if (request.description().isBlank()) {
                throw new ValidationException(
                        "Description cannot be blank",
                        List.of(new com.ospysin.shared.error.InvalidParam("description", "Description cannot be blank"))
                );
            }
            finding.setDescription(request.description().trim());
        }

        if (request.severity() != null) {
            finding.setSeverity(request.severity());
        }

        if (request.confidence() != null) {
            finding.setConfidence(request.confidence());
        }

        if (request.remediation() != null) {
            finding.setRemediation(request.remediation().trim());
        }

        if (targetStatus != null && targetStatus != currentStatus) {
            finding.setStatus(targetStatus);
        }

        Instant now = clock.instant();
        finding.setUpdatedAt(now);
        finding = findingRepository.save(finding);

        if (targetStatus == FindingStatus.REJECTED) {
            AuditEvent auditEvent = AuditEvent.builder()
                    .session(session)
                    .eventType(AuditEventType.FINDING_REJECTED)
                    .payload(Map.of(
                            "findingId", finding.getId().toString(),
                            "previousStatus", currentStatus.name(),
                            "rejectionReason", finding.getRejectionReason()
                    ))
                    .timestamp(now)
                    .build();
            auditEventRepository.save(auditEvent);
        }

        List<Evidence> evidenceList = evidenceRepository.findByFindingIdOrderByCreatedAtAsc(findingId);
        List<EvidenceResponse> evidenceResponses = evidenceList.stream()
                .map(e -> new EvidenceResponse(
                        e.getId(),
                        e.getFinding().getId(),
                        e.getResult().getId(),
                        e.getResult().getExecution().getId(),
                        e.getResult().getExecution().getToolId(),
                        e.getSnippet(),
                        e.getCreatedAt()
                ))
                .toList();

        return new FindingResponse(
                finding.getId(),
                session.getId(),
                finding.getObservation() != null ? finding.getObservation().getId() : null,
                finding.getTitle(),
                finding.getDescription(),
                finding.getSeverity(),
                finding.getConfidence(),
                finding.getStatus(),
                finding.getRejectionReason(),
                finding.getRemediation(),
                evidenceResponses,
                finding.getCreatedAt(),
                finding.getUpdatedAt()
        );
    }

    /**
     * Attaches an evidence snippet from an existing ToolResult to a finding.
     */
    @Transactional
    public EvidenceResponse attachEvidence(UUID sessionId, UUID findingId, CreateEvidenceRequest request) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        if (session.getState() == SessionState.ABORTED) {
            throw new ConflictException("Cannot attach evidence in an ABORTED session");
        }

        Finding finding = findingRepository.findByIdAndSessionId(findingId, sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Finding not found: " + findingId));

        if (finding.getStatus() == FindingStatus.REJECTED || finding.getStatus() == FindingStatus.FALSE_POSITIVE) {
            throw new ConflictException("Cannot attach evidence to finding in state: " + finding.getStatus());
        }

        ToolResult result = toolResultRepository.findById(request.resultId())
                .or(() -> toolResultRepository.findByExecutionId(request.resultId()))
                .orElseThrow(() -> new ResourceNotFoundException("Tool result not found: " + request.resultId()));

        // BOLA Guard 2
        if (!result.getExecution().getSession().getId().equals(sessionId)) {
            throw new ResourceNotFoundException("Tool result not found in session: " + request.resultId());
        }

        Instant now = clock.instant();
        Evidence evidence = Evidence.builder()
                .finding(finding)
                .result(result)
                .snippet(request.snippet().trim())
                .createdAt(now)
                .build();

        evidence = evidenceRepository.save(evidence);

        return new EvidenceResponse(
                evidence.getId(),
                finding.getId(),
                result.getId(),
                result.getExecution().getId(),
                result.getExecution().getToolId(),
                evidence.getSnippet(),
                evidence.getCreatedAt()
        );
    }
}
