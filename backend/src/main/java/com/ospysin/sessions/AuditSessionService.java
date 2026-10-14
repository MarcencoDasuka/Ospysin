package com.ospysin.sessions;

import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.findings.FindingRepository;
import com.ospysin.findings.FindingStatus;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.sessions.dto.CreateSessionRequest;
import com.ospysin.sessions.dto.SessionPageResponse;
import com.ospysin.sessions.dto.SessionResponse;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ResourceNotFoundException;
import com.ospysin.shared.error.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
public class AuditSessionService {

    private final ScopeAttestationRegistry scopeAttestationRegistry;
    private final PolicyEngine policyEngine;
    private final AuditSessionRepository auditSessionRepository;
    private final ToolExecutionRepository toolExecutionRepository;
    private final FindingRepository findingRepository;
    private final AuditSessionTxService auditSessionTxService;

    public SessionResponse createSession(CreateSessionRequest request) {
        // 1. Validate Scope Attestation (server-authoritative)
        scopeAttestationRegistry.validate(request.scopeAcknowledged(), request.scopeAckVersion());
        String statementText = scopeAttestationRegistry.getStatement(request.scopeAckVersion());
        String statementHash = scopeAttestationRegistry.computeDigest(statementText);

        // 2. Pre-Flight Policy Evaluation OUTSIDE @Transactional (performs network DNS I/O)
        PolicyDecision decision = policyEngine.evaluate(request.targetUrl(), request.mode(), null);
        if (!decision.allowed()) {
            policyEngine.recordAudit(null, decision);
            throw new PolicyViolationException(
                    "Policy violation: " + decision.reason(),
                    List.of(new InvalidParam("targetUrl", decision.reason()))
            );
        }

        // 3. Open Transactional Persistence Boundary
        return auditSessionTxService.initializeSession(request, decision, statementText, statementHash);
    }

    @Transactional(readOnly = true)
    public SessionPageResponse getSessions(int page, int size) {
        List<InvalidParam> invalidParams = new ArrayList<>();
        if (page < 0) {
            invalidParams.add(new InvalidParam("page", "Page index must not be negative"));
        }
        if (size < 1 || size > 100) {
            invalidParams.add(new InvalidParam("size", "Page size must be between 1 and 100"));
        }
        if (!invalidParams.isEmpty()) {
            throw new ValidationException("Invalid pagination parameters", invalidParams);
        }

        PageRequest pageRequest = PageRequest.of(page, size);
        Page<AuditSession> sessionPage = auditSessionRepository.findAllByOrderByCreatedAtDesc(pageRequest);

        List<AuditSession> sessions = sessionPage.getContent();
        if (sessions.isEmpty()) {
            return new SessionPageResponse(
                    List.of(),
                    sessionPage.getNumber(),
                    sessionPage.getSize(),
                    sessionPage.getTotalElements(),
                    sessionPage.getTotalPages()
            );
        }

        List<UUID> sessionIds = sessions.stream().map(AuditSession::getId).toList();

        // Batch execution counts to prevent N+1 queries
        Map<UUID, Long> executionCounts = new HashMap<>();
        List<Object[]> execResults = toolExecutionRepository.countExecutionsBySessionIds(sessionIds);
        for (Object[] row : execResults) {
            executionCounts.put((UUID) row[0], ((Number) row[1]).longValue());
        }

        // Batch finding counts to prevent N+1 queries
        Map<UUID, Long> findingCounts = new HashMap<>();
        List<Object[]> findingResults = findingRepository.countFindingsBySessionIds(sessionIds);
        for (Object[] row : findingResults) {
            findingCounts.put((UUID) row[0], ((Number) row[1]).longValue());
        }

        List<SessionResponse> content = sessions.stream()
                .map(s -> new SessionResponse(
                        s.getId(),
                        s.getTargetUrl(),
                        s.getMode(),
                        s.getState(),
                        s.isScopeAcknowledged(),
                        s.getScopeAckVersion(),
                        s.getScopeAckHash(),
                        s.getScopeAckTimestamp(),
                        executionCounts.getOrDefault(s.getId(), 0L),
                        findingCounts.getOrDefault(s.getId(), 0L),
                        s.getCreatedAt(),
                        s.getUpdatedAt()
                ))
                .toList();

        return new SessionPageResponse(
                content,
                sessionPage.getNumber(),
                sessionPage.getSize(),
                sessionPage.getTotalElements(),
                sessionPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public SessionResponse getSession(UUID id) {
        AuditSession session = auditSessionRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + id));

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

    public SessionResponse completeSession(UUID id) {
        return auditSessionTxService.completeSession(id);
    }

    public SessionResponse abortSession(UUID id) {
        return auditSessionTxService.abortSession(id);
    }
}
