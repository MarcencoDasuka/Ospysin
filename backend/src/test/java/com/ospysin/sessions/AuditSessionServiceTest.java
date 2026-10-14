package com.ospysin.sessions;

import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.findings.FindingRepository;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.sessions.dto.CreateSessionRequest;
import com.ospysin.sessions.dto.SessionPageResponse;
import com.ospysin.sessions.dto.SessionResponse;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ResourceNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuditSessionServiceTest {

    private ScopeAttestationRegistry scopeAttestationRegistry;
    private PolicyEngine policyEngine;
    private AuditSessionRepository auditSessionRepository;
    private ToolExecutionRepository toolExecutionRepository;
    private FindingRepository findingRepository;
    private AuditSessionTxService auditSessionTxService;
    private AuditSessionService auditSessionService;

    @BeforeEach
    void setUp() {
        scopeAttestationRegistry = mock(ScopeAttestationRegistry.class);
        policyEngine = mock(PolicyEngine.class);
        auditSessionRepository = mock(AuditSessionRepository.class);
        toolExecutionRepository = mock(ToolExecutionRepository.class);
        findingRepository = mock(FindingRepository.class);
        auditSessionTxService = mock(AuditSessionTxService.class);

        auditSessionService = new AuditSessionService(
                scopeAttestationRegistry,
                policyEngine,
                auditSessionRepository,
                toolExecutionRepository,
                findingRepository,
                auditSessionTxService
        );
    }

    @Test
    @DisplayName("createSession() throws PolicyViolationException outside @Transactional when policy engine rejects")
    void createSessionPolicyViolation() {
        CreateSessionRequest request = new CreateSessionRequest(
                "http://127.0.0.1",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        when(scopeAttestationRegistry.getStatement("1.0.0")).thenReturn("statement text");
        when(scopeAttestationRegistry.computeDigest("statement text")).thenReturn("sha256hash");
        PolicyDecision rejectedDecision = new PolicyDecision(false, "Loopback is prohibited in PUBLIC mode", "127.0.0.1", null, SessionMode.PUBLIC, 0L);
        when(policyEngine.evaluate("http://127.0.0.1", SessionMode.PUBLIC, null))
                .thenReturn(rejectedDecision);

        assertThatThrownBy(() -> auditSessionService.createSession(request))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("Loopback is prohibited")
                .satisfies(ex -> {
                    PolicyViolationException pve = (PolicyViolationException) ex;
                    assertThat(pve.getInvalidParams()).hasSize(1);
                    assertThat(pve.getInvalidParams().get(0).name()).isEqualTo("targetUrl");
                });

        verify(policyEngine).recordAudit(null, rejectedDecision);
        verifyNoInteractions(auditSessionTxService);
    }

    @Test
    @DisplayName("createSession() succeeds and delegates to AuditSessionTxService")
    void createSessionSuccess() throws Exception {
        CreateSessionRequest request = new CreateSessionRequest(
                "https://example.com",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        when(scopeAttestationRegistry.getStatement("1.0.0")).thenReturn("statement text");
        when(scopeAttestationRegistry.computeDigest("statement text")).thenReturn("sha256hash");
        PolicyDecision decision = new PolicyDecision(
                true,
                "Authorized",
                "example.com",
                InetAddress.getByName("93.184.216.34"),
                SessionMode.PUBLIC,
                0L
        );
        when(policyEngine.evaluate("https://example.com", SessionMode.PUBLIC, null)).thenReturn(decision);

        SessionResponse mockResponse = new SessionResponse(
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                SessionState.ACTIVE,
                true,
                "1.0.0",
                "sha256hash",
                Instant.now(),
                0L,
                0L,
                Instant.now(),
                Instant.now()
        );
        when(auditSessionTxService.initializeSession(request, decision, "statement text", "sha256hash"))
                .thenReturn(mockResponse);

        SessionResponse response = auditSessionService.createSession(request);
        assertThat(response).isEqualTo(mockResponse);
        verify(auditSessionTxService).initializeSession(request, decision, "statement text", "sha256hash");
    }

    @Test
    @DisplayName("getSession() throws ResourceNotFoundException when session not found")
    void getSessionNotFound() {
        UUID unknownId = UUID.randomUUID();
        when(auditSessionRepository.findById(unknownId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> auditSessionService.getSession(unknownId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Session not found");
    }

    @Test
    @DisplayName("getSessions() returns empty content when repository page is empty")
    void getSessionsEmptyPage() {
        Page<AuditSession> emptyPage = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);
        when(auditSessionRepository.findAllByOrderByCreatedAtDesc(any(PageRequest.class)))
                .thenReturn(emptyPage);

        SessionPageResponse response = auditSessionService.getSessions(0, 20);
        assertThat(response.content()).isEmpty();
        assertThat(response.totalElements()).isEqualTo(0);
        verifyNoInteractions(toolExecutionRepository, findingRepository);
    }
}
