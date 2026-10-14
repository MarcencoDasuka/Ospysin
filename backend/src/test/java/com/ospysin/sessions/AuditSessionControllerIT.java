package com.ospysin.sessions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.AbstractIntegrationTest;
import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.findings.*;
import com.ospysin.policy.DnsResolver;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.scope.ScopeAssetRepository;
import com.ospysin.sessions.dto.CreateSessionRequest;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class AuditSessionControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private DnsResolver dnsResolver;

    @Autowired
    private AuditSessionRepository auditSessionRepository;

    @Autowired
    private EngagementRepository engagementRepository;

    @Autowired
    private ScopeAssetRepository scopeAssetRepository;

    @Autowired
    private ToolExecutionRepository toolExecutionRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @BeforeEach
    void setUp() throws UnknownHostException {
        when(dnsResolver.resolveAll("example.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("93.184.216.34")});
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions in PUBLIC mode creates Engagement, ScopeAsset, AuditSession, and 3 AuditEvents")
    void createSessionPublicModeSuccess() throws Exception {
        CreateSessionRequest request = new CreateSessionRequest(
                "https://example.com/target",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        MvcResult result = mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.targetUrl").value("https://example.com/target"))
                .andExpect(jsonPath("$.mode").value("PUBLIC"))
                .andExpect(jsonPath("$.state").value("ACTIVE"))
                .andExpect(jsonPath("$.scopeAcknowledged").value(true))
                .andExpect(jsonPath("$.scopeAckVersion").value("1.0.0"))
                .andExpect(jsonPath("$.scopeAckHash", matchesPattern("^[0-9a-f]{64}$")))
                .andExpect(jsonPath("$.scopeAckTimestamp").isNotEmpty())
                .andExpect(jsonPath("$.stepCount").value(0))
                .andExpect(jsonPath("$.findingCount").value(0))
                .andExpect(jsonPath("$.createdAt").isNotEmpty())
                .andExpect(jsonPath("$.updatedAt").isNotEmpty())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        UUID sessionId = UUID.fromString(objectMapper.readTree(responseBody).get("id").asText());

        // Verify AuditSession persisted
        AuditSession session = auditSessionRepository.findById(sessionId).orElseThrow();
        assertThat(session.getTargetUrl()).isEqualTo("https://example.com/target");
        assertThat(session.getMode()).isEqualTo(SessionMode.PUBLIC);
        assertThat(session.getState()).isEqualTo(SessionState.ACTIVE);

        // Verify Engagement persisted
        UUID engagementId = session.getEngagement().getId();
        Engagement engagement = engagementRepository.findById(engagementId).orElseThrow();
        assertThat(engagement.getTitle()).isEqualTo("Ad-Hoc Audit: example.com");
        assertThat(engagement.getProject().getId())
                .isEqualTo(UUID.fromString("00000000-0000-0000-0000-000000000001"));

        // Verify ScopeAsset persisted
        List<ScopeAsset> assets = scopeAssetRepository.findByEngagementId(engagement.getId());
        assertThat(assets).hasSize(1);
        assertThat(assets.get(0).getValue()).isEqualTo("example.com");
        assertThat(assets.get(0).getAssetType()).isEqualTo(AssetType.FQDN);

        // Verify 3 immutable AuditEvents persisted
        List<AuditEvent> events = auditEventRepository.findBySessionIdOrderByTimestampAsc(sessionId);
        assertThat(events).hasSize(3);

        AuditEvent scopeAck = events.stream()
                .filter(e -> e.getEventType() == AuditEventType.SCOPE_ACKNOWLEDGED)
                .findFirst()
                .orElseThrow();
        assertThat(scopeAck.getPayload()).containsEntry("version", "1.0.0");
        assertThat(scopeAck.getPayload()).containsKey("hash");

        AuditEvent policyEval = events.stream()
                .filter(e -> e.getEventType() == AuditEventType.POLICY_EVALUATED)
                .findFirst()
                .orElseThrow();
        assertThat(policyEval.getPayload()).containsEntry("allowed", true);
        assertThat(policyEval.getPayload()).containsEntry("targetHost", "example.com");

        AuditEvent sessionStarted = events.stream()
                .filter(e -> e.getEventType() == AuditEventType.SESSION_STARTED)
                .findFirst()
                .orElseThrow();
        assertThat(sessionStarted.getPayload()).containsEntry("targetHost", "example.com");
        assertThat(sessionStarted.getPayload()).containsEntry("resolvedIp", "93.184.216.34");
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions in PUBLIC mode targeting private IP or loopback is rejected with 403 Forbidden")
    void createSessionPublicModeRejectsPrivateIps() throws Exception {
        CreateSessionRequest privateIpRequest = new CreateSessionRequest(
                "http://192.168.1.100:8080/admin",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(privateIpRequest)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/policy-violation"))
                .andExpect(jsonPath("$.invalidParams[0].name").value("targetUrl"))
                .andExpect(jsonPath("$.invalidParams[0].reason", containsStringIgnoringCase("RFC 1918")));

        CreateSessionRequest loopbackRequest = new CreateSessionRequest(
                "http://127.0.0.1:8080/admin",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loopbackRequest)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/policy-violation"))
                .andExpect(jsonPath("$.invalidParams[0].name").value("targetUrl"))
                .andExpect(jsonPath("$.invalidParams[0].reason", containsStringIgnoringCase("Loopback")));

        List<AuditEvent> orphanEvents = auditEventRepository.findBySessionIsNull();
        assertThat(orphanEvents).isNotEmpty();
        boolean hasRejectedPolicyEvent = orphanEvents.stream().anyMatch(e ->
                e.getEventType() == AuditEventType.POLICY_EVALUATED &&
                Boolean.FALSE.equals(e.getPayload().get("allowed"))
        );
        assertThat(hasRejectedPolicyEvent).isTrue();
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions in LOCAL mode permits loopback but rejects cloud metadata")
    void createSessionLocalModeEvaluations() throws Exception {
        // LOCAL mode allows 127.0.0.1
        CreateSessionRequest localRequest = new CreateSessionRequest(
                "http://127.0.0.1:8080/dashboard",
                SessionMode.LOCAL,
                true,
                "1.0.0"
        );

        MvcResult result = mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(localRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.mode").value("LOCAL"))
                .andExpect(jsonPath("$.state").value("ACTIVE"))
                .andReturn();

        UUID sessionId = UUID.fromString(objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText());
        AuditSession session = auditSessionRepository.findById(sessionId).orElseThrow();
        List<ScopeAsset> assets = scopeAssetRepository.findByEngagementId(session.getEngagement().getId());
        assertThat(assets.get(0).getAssetType()).isEqualTo(AssetType.IP);

        // LOCAL mode rejects cloud metadata 169.254.169.254
        CreateSessionRequest metadataRequest = new CreateSessionRequest(
                "http://169.254.169.254/latest/meta-data",
                SessionMode.LOCAL,
                true,
                "1.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(metadataRequest)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/policy-violation"))
                .andExpect(jsonPath("$.invalidParams[0].name").value("targetUrl"))
                .andExpect(jsonPath("$.invalidParams[0].reason", containsStringIgnoringCase("Metadata")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions with scopeAcknowledged false or invalid version returns 422 Unprocessable Entity")
    void createSessionAttestationFailures() throws Exception {
        CreateSessionRequest unackRequest = new CreateSessionRequest(
                "https://example.com/target",
                SessionMode.PUBLIC,
                false,
                "1.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(unackRequest)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/validation-error"))
                .andExpect(jsonPath("$.invalidParams[*].name").value(hasItem("scopeAcknowledged")));

        CreateSessionRequest badVersionRequest = new CreateSessionRequest(
                "https://example.com/target",
                SessionMode.PUBLIC,
                true,
                "2.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(badVersionRequest)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/validation-error"))
                .andExpect(jsonPath("$.invalidParams[*].name").value(hasItem("scopeAckVersion")));

        CreateSessionRequest oversizedUrlRequest = new CreateSessionRequest(
                "https://example.com/" + "x".repeat(500),
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(oversizedUrlRequest)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/validation-error"))
                .andExpect(jsonPath("$.invalidParams[*].name").value(hasItem("targetUrl")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("GET /api/sessions and GET /api/sessions/{id} return accurate counts and metadata")
    void querySessionsAndMetadata() throws Exception {
        // 1. Create session via POST
        CreateSessionRequest request = new CreateSessionRequest(
                "https://example.com/query-test",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        MvcResult postResult = mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andReturn();

        UUID sessionId = UUID.fromString(objectMapper.readTree(postResult.getResponse().getContentAsString()).get("id").asText());
        AuditSession session = auditSessionRepository.findById(sessionId).orElseThrow();

        // 2. Add 2 tool executions and 1 finding
        ToolExecution exec1 = ToolExecution.builder()
                .session(session)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .build();
        ToolExecution exec2 = ToolExecution.builder()
                .session(session)
                .toolId("tls_info")
                .status(ExecutionStatus.COMPLETED)
                .build();
        toolExecutionRepository.saveAll(List.of(exec1, exec2));

        Finding confirmedFinding = Finding.builder()
                .session(session)
                .title("Missing HSTS")
                .description("Target does not implement Strict-Transport-Security")
                .severity(FindingSeverity.MEDIUM)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .build();
        Finding rejectedFinding = Finding.builder()
                .session(session)
                .title("False Positive Header")
                .description("Header marked as false positive by auditor")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.REJECTED)
                .rejectionReason("Verified protected by reverse proxy")
                .build();
        findingRepository.saveAll(List.of(confirmedFinding, rejectedFinding));

        // 3. GET /api/sessions/{id} returns accurate counts
        mockMvc.perform(get("/api/sessions/{id}", sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(sessionId.toString()))
                .andExpect(jsonPath("$.stepCount").value(2))
                .andExpect(jsonPath("$.findingCount").value(1));

        // 4. GET /api/sessions returns page with accurate counts
        mockMvc.perform(get("/api/sessions?page=0&size=20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", not(empty())))
                .andExpect(jsonPath("$.content[?(@.id == '" + sessionId + "')].stepCount", contains(2)))
                .andExpect(jsonPath("$.content[?(@.id == '" + sessionId + "')].findingCount", contains(1)));

        // 5. GET /api/sessions/{unknownId} returns 404
        mockMvc.perform(get("/api/sessions/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/resource-not-found"));

        // 6. Invalid pagination parameters return 422
        mockMvc.perform(get("/api/sessions?page=-1&size=0"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.invalidParams[*].name").value(hasItems("page", "size")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions/{id}/complete rejects active executions with 409 and completes cleanly when idle")
    void completeSessionLifecycleTransitions() throws Exception {
        CreateSessionRequest request = new CreateSessionRequest(
                "https://example.com/complete-test",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        MvcResult postResult = mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andReturn();

        UUID sessionId = UUID.fromString(objectMapper.readTree(postResult.getResponse().getContentAsString()).get("id").asText());
        AuditSession session = auditSessionRepository.findById(sessionId).orElseThrow();

        // 1. Add RUNNING execution
        ToolExecution runningExec = ToolExecution.builder()
                .session(session)
                .toolId("http_headers")
                .status(ExecutionStatus.RUNNING)
                .build();
        runningExec = toolExecutionRepository.save(runningExec);

        // 2. /complete fails with 409 Conflict
        mockMvc.perform(post("/api/sessions/{id}/complete", sessionId).with(csrf()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/conflict"))
                .andExpect(jsonPath("$.detail", containsString("PENDING or RUNNING")));

        // 3. Mark execution COMPLETED
        runningExec.setStatus(ExecutionStatus.COMPLETED);
        toolExecutionRepository.save(runningExec);

        // 4. /complete succeeds
        mockMvc.perform(post("/api/sessions/{id}/complete", sessionId).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(sessionId.toString()))
                .andExpect(jsonPath("$.state").value("COMPLETED"));

        AuditSession updatedSession = auditSessionRepository.findById(sessionId).orElseThrow();
        assertThat(updatedSession.getState()).isEqualTo(SessionState.COMPLETED);

        // 5. Calling /complete again on COMPLETED session returns 409 Conflict
        mockMvc.perform(post("/api/sessions/{id}/complete", sessionId).with(csrf()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail", containsString("already in terminal state")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions/{id}/abort cancels active executions, increments leaseEpoch, and sets ABORTED state")
    void abortSessionCancelsExecutionsAndFencesWorkers() throws Exception {
        CreateSessionRequest request = new CreateSessionRequest(
                "https://example.com/abort-test",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        MvcResult postResult = mockMvc.perform(post("/api/sessions")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andReturn();

        UUID sessionId = UUID.fromString(objectMapper.readTree(postResult.getResponse().getContentAsString()).get("id").asText());
        AuditSession session = auditSessionRepository.findById(sessionId).orElseThrow();

        // Add 1 PENDING execution and 1 RUNNING execution
        ToolExecution pendingExec = ToolExecution.builder()
                .session(session)
                .toolId("http_headers")
                .status(ExecutionStatus.PENDING)
                .leaseEpoch(0)
                .build();
        ToolExecution runningExec = ToolExecution.builder()
                .session(session)
                .toolId("tls_info")
                .status(ExecutionStatus.RUNNING)
                .leaseEpoch(2)
                .build();
        pendingExec = toolExecutionRepository.save(pendingExec);
        runningExec = toolExecutionRepository.save(runningExec);

        // Abort session
        mockMvc.perform(post("/api/sessions/{id}/abort", sessionId).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(sessionId.toString()))
                .andExpect(jsonPath("$.state").value("ABORTED"));

        // Verify database state: session is ABORTED
        AuditSession abortedSession = auditSessionRepository.findById(sessionId).orElseThrow();
        assertThat(abortedSession.getState()).isEqualTo(SessionState.ABORTED);

        // Verify executions are CANCELLED and leaseEpoch is incremented (fencing out in-flight workers)
        ToolExecution updatedPending = toolExecutionRepository.findById(pendingExec.getId()).orElseThrow();
        assertThat(updatedPending.getStatus()).isEqualTo(ExecutionStatus.CANCELLED);
        assertThat(updatedPending.getLeaseEpoch()).isEqualTo(1); // 0 + 1
        assertThat(updatedPending.getFailureReason()).isEqualTo("Session aborted by operator");
        assertThat(updatedPending.getEndedAt()).isNotNull();

        ToolExecution updatedRunning = toolExecutionRepository.findById(runningExec.getId()).orElseThrow();
        assertThat(updatedRunning.getStatus()).isEqualTo(ExecutionStatus.CANCELLED);
        assertThat(updatedRunning.getLeaseEpoch()).isEqualTo(3); // 2 + 1
        assertThat(updatedRunning.getFailureReason()).isEqualTo("Session aborted by operator");
        assertThat(updatedRunning.getEndedAt()).isNotNull();

        // Verify SESSION_ABORTED AuditEvent recorded
        List<AuditEvent> events = auditEventRepository.findBySessionIdOrderByTimestampAsc(sessionId);
        boolean hasAbortEvent = events.stream().anyMatch(e -> e.getEventType() == AuditEventType.SESSION_ABORTED);
        assertThat(hasAbortEvent).isTrue();

        // Calling /abort again on ABORTED session returns 409 Conflict
        mockMvc.perform(post("/api/sessions/{id}/abort", sessionId).with(csrf()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail", containsString("already in terminal state")));
    }

    @Test
    @DisplayName("Unauthenticated request to /api/sessions returns 401 Unauthorized")
    void unauthenticatedRequestReturns401() throws Exception {
        mockMvc.perform(get("/api/sessions"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/unauthorized"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("POST /api/sessions without CSRF token returns 403 Forbidden")
    void missingCsrfTokenReturns403() throws Exception {
        CreateSessionRequest request = new CreateSessionRequest(
                "https://example.com/csrf-test",
                SessionMode.PUBLIC,
                true,
                "1.0.0"
        );

        mockMvc.perform(post("/api/sessions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/access-denied"));
    }
}
