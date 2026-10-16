package com.ospysin.findings;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.AbstractIntegrationTest;
import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.engagements.EngagementStatus;
import com.ospysin.evidence.Evidence;
import com.ospysin.evidence.EvidenceRepository;
import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.findings.dto.CreateEvidenceRequest;
import com.ospysin.findings.dto.CreateFindingRequest;
import com.ospysin.findings.dto.UpdateFindingRequest;
import com.ospysin.observations.Observation;
import com.ospysin.observations.ObservationRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.projects.Project;
import com.ospysin.projects.ProjectRepository;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.scope.ScopeAssetRepository;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.sessions.SessionMode;
import com.ospysin.sessions.SessionState;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import org.springframework.test.annotation.DirtiesContext;
import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@AutoConfigureMockMvc
class FindingCurationAndReportIT extends AbstractIntegrationTest {

    private static final UUID DEFAULT_PROJECT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private EngagementRepository engagementRepository;

    @Autowired
    private ScopeAssetRepository scopeAssetRepository;

    @Autowired
    private AuditSessionRepository auditSessionRepository;

    @Autowired
    private ToolExecutionRepository toolExecutionRepository;

    @Autowired
    private ToolResultRepository toolResultRepository;

    @Autowired
    private ObservationRepository observationRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private EvidenceRepository evidenceRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    private AuditSession sessionA;
    private AuditSession sessionB;
    private ToolExecution executionA;
    private ToolResult resultA;
    private Observation observationA;

    private ToolExecution executionB;
    private ToolResult resultB;
    private Observation observationB;

    @BeforeEach
    void setUp() {
        Project project = projectRepository.findById(DEFAULT_PROJECT_ID).orElseGet(() ->
                projectRepository.save(Project.builder()
                        .name("Default Project")
                        .description("System container")
                        .build()));

        Engagement engagement = engagementRepository.save(Engagement.builder()
                .project(project)
                .title("Phase 17 Engagement " + UUID.randomUUID())
                .startDate(LocalDate.now())
                .status(EngagementStatus.ACTIVE)
                .build());

        scopeAssetRepository.save(ScopeAsset.builder()
                .engagement(engagement)
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(false)
                .build());

        // Session A
        sessionA = auditSessionRepository.save(AuditSession.builder()
                .engagement(engagement)
                .targetUrl("https://example.com/app-a")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .scopeAckTimestamp(Instant.now())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build());

        executionA = toolExecutionRepository.save(ToolExecution.builder()
                .session(sessionA)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .durationMs(150L)
                .createdAt(Instant.now())
                .startedAt(Instant.now())
                .endedAt(Instant.now())
                .build());

        resultA = toolResultRepository.save(ToolResult.builder()
                .execution(executionA)
                .rawOutput("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Frame-Options: SAMEORIGIN")
                .parsedData(Map.of("statusCode", 200, "server", "nginx/1.24.0"))
                .score(85)
                .hasErrors(false)
                .createdAt(Instant.now())
                .build());

        observationA = observationRepository.save(Observation.builder()
                .result(resultA)
                .category("SECURITY_HEADERS")
                .description("Missing Content-Security-Policy header in HTTP response")
                .severityHeuristic(SeverityHeuristic.MEDIUM)
                .detectedAt(Instant.now())
                .build());

        // Session B (for cross-session / BOLA tests)
        sessionB = auditSessionRepository.save(AuditSession.builder()
                .engagement(engagement)
                .targetUrl("https://example.com/app-b")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckHash("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .scopeAckTimestamp(Instant.now())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build());

        executionB = toolExecutionRepository.save(ToolExecution.builder()
                .session(sessionB)
                .toolId("tls_info")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .durationMs(200L)
                .createdAt(Instant.now())
                .startedAt(Instant.now())
                .endedAt(Instant.now())
                .build());

        resultB = toolResultRepository.save(ToolResult.builder()
                .execution(executionB)
                .rawOutput("TLS 1.3 / TLS_AES_256_GCM_SHA384")
                .parsedData(Map.of("protocol", "TLSv1.3"))
                .hasErrors(false)
                .createdAt(Instant.now())
                .build());

        observationB = observationRepository.save(Observation.builder()
                .result(resultB)
                .category("TLS")
                .description("Self-signed certificate in chain")
                .severityHeuristic(SeverityHeuristic.HIGH)
                .detectedAt(Instant.now())
                .build());
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Promote Observation to Finding (201 Created) and verify FINDING_CREATED audit event")
    void testPromoteObservationToFinding() throws Exception {
        CreateFindingRequest request = new CreateFindingRequest(
                observationA.getId(),
                "Missing Content-Security-Policy",
                "The web server fails to supply a Content-Security-Policy header.",
                FindingSeverity.MEDIUM,
                null, // will default to FIRM
                "Add Content-Security-Policy: default-src 'self' to server config."
        );

        MvcResult result = mockMvc.perform(post("/api/sessions/" + sessionA.getId() + "/findings")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.sessionId").value(sessionA.getId().toString()))
                .andExpect(jsonPath("$.observationId").value(observationA.getId().toString()))
                .andExpect(jsonPath("$.title").value("Missing Content-Security-Policy"))
                .andExpect(jsonPath("$.severity").value("MEDIUM"))
                .andExpect(jsonPath("$.confidence").value("FIRM"))
                .andExpect(jsonPath("$.status").value("OPEN"))
                .andExpect(jsonPath("$.remediation").value("Add Content-Security-Policy: default-src 'self' to server config."))
                .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        String findingIdStr = objectMapper.readTree(responseJson).get("id").asText();

        // Verify AuditEvent recorded
        List<AuditEvent> auditEvents = auditEventRepository.findBySessionIdOrderByTimestampAsc(sessionA.getId());
        AuditEvent findingCreatedEvent = auditEvents.stream()
                .filter(e -> e.getEventType() == AuditEventType.FINDING_CREATED)
                .findFirst()
                .orElse(null);

        assertThat(findingCreatedEvent).isNotNull();
        assertThat(findingCreatedEvent.getPayload()).containsEntry("findingId", findingIdStr);
        assertThat(findingCreatedEvent.getPayload()).containsEntry("title", "Missing Content-Security-Policy");
        assertThat(findingCreatedEvent.getPayload()).containsEntry("severity", "MEDIUM");
        assertThat(findingCreatedEvent.getPayload()).containsEntry("observationId", observationA.getId().toString());
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Create manual Finding without observationId (201 Created) defaults confidence to TENTATIVE")
    void testCreateManualFinding() throws Exception {
        CreateFindingRequest request = new CreateFindingRequest(
                null,
                "Exposed Administrative Portal",
                "Discovered unprotected admin dashboard at /admin",
                FindingSeverity.HIGH,
                null, // will default to TENTATIVE
                "Enforce multi-factor authentication or restrict /admin to internal IP ranges."
        );

        mockMvc.perform(post("/api/sessions/" + sessionA.getId() + "/findings")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.sessionId").value(sessionA.getId().toString()))
                .andExpect(jsonPath("$.observationId").doesNotExist())
                .andExpect(jsonPath("$.confidence").value("TENTATIVE"))
                .andExpect(jsonPath("$.status").value("OPEN"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("BOLA Guard: Promoting observation belonging to Session B into Session A fails with 404")
    void testBolaCrossSessionObservationPromotion() throws Exception {
        CreateFindingRequest request = new CreateFindingRequest(
                observationB.getId(), // belongs to sessionB
                "Cross Session Exploit Attempt",
                "Attempting to promote observation from Session B into Session A",
                FindingSeverity.HIGH,
                null,
                null
        );

        mockMvc.perform(post("/api/sessions/" + sessionA.getId() + "/findings")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title").value("Resource Not Found"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("BOLA Guard: Updating finding belonging to Session B via Session A URL fails with 404")
    void testBolaCrossSessionFindingUpdate() throws Exception {
        // Create finding in Session B
        Finding findingInB = findingRepository.save(Finding.builder()
                .session(sessionB)
                .title("Finding in Session B")
                .description("Sensitive data in Session B")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.OPEN)
                .build());

        UpdateFindingRequest updateRequest = new UpdateFindingRequest(
                "Tampered Title",
                null,
                null,
                null,
                FindingStatus.CONFIRMED,
                null,
                null
        );

        // Attempt to update findingInB using sessionA path
        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + findingInB.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title").value("Resource Not Found"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("BOLA Guard: Attaching evidence with resultId from Session B into finding in Session A fails with 404")
    void testBolaCrossSessionEvidenceAttachment() throws Exception {
        Finding findingInA = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Finding in Session A")
                .description("Legitimate finding in Session A")
                .severity(FindingSeverity.MEDIUM)
                .confidence(FindingConfidence.FIRM)
                .status(FindingStatus.OPEN)
                .build());

        CreateEvidenceRequest evidenceRequest = new CreateEvidenceRequest(
                resultB.getId(), // result from Session B!
                "Forensic snippet from Session B"
        );

        mockMvc.perform(post("/api/sessions/" + sessionA.getId() + "/findings/" + findingInA.getId() + "/evidence")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(evidenceRequest)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title").value("Resource Not Found"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("State Machine: OPEN -> CONFIRMED succeeds (200 OK)")
    void testStateMachineOpenToConfirmed() throws Exception {
        Finding finding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Status Transition Test")
                .description("Testing valid transition")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.OPEN)
                .build());

        UpdateFindingRequest request = new UpdateFindingRequest(
                null, null, null, null, FindingStatus.CONFIRMED, null, null
        );

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + finding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CONFIRMED"));

        Finding reloaded = findingRepository.findById(finding.getId()).orElseThrow();
        assertThat(reloaded.getStatus()).isEqualTo(FindingStatus.CONFIRMED);
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("State Machine & DB Invariant: CONFIRMED -> REJECTED without rejectionReason fails with 422")
    void testRejectWithoutReasonFails() throws Exception {
        Finding finding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Rejection Invariant Test")
                .description("Requires reason when rejected")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .build());

        UpdateFindingRequest requestNoReason = new UpdateFindingRequest(
                null, null, null, null, FindingStatus.REJECTED, null, null
        );

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + finding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestNoReason)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.invalidParams[0].name").value("rejectionReason"));

        UpdateFindingRequest requestBlankReason = new UpdateFindingRequest(
                null, null, null, null, FindingStatus.REJECTED, "   ", null
        );

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + finding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBlankReason)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.invalidParams[0].name").value("rejectionReason"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("State Machine: CONFIRMED -> REJECTED with valid reason succeeds, records FINDING_REJECTED event, decrements session active findingCount")
    void testConfirmedToRejectedWithReason() throws Exception {
        Finding finding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Rejection Success Test")
                .description("Testing successful rejection")
                .severity(FindingSeverity.MEDIUM)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .build());

        // Verify active finding count in session is 1
        mockMvc.perform(get("/api/sessions/" + sessionA.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(1));

        UpdateFindingRequest request = new UpdateFindingRequest(
                null, null, null, null, FindingStatus.REJECTED, "Verified protected by external cloud WAF rule.", null
        );

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + finding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"))
                .andExpect(jsonPath("$.rejectionReason").value("Verified protected by external cloud WAF rule."));

        // Verify active finding count decremented to 0
        mockMvc.perform(get("/api/sessions/" + sessionA.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(0));

        // Verify FINDING_REJECTED AuditEvent recorded
        List<AuditEvent> auditEvents = auditEventRepository.findBySessionIdOrderByTimestampAsc(sessionA.getId());
        AuditEvent rejectedEvent = auditEvents.stream()
                .filter(e -> e.getEventType() == AuditEventType.FINDING_REJECTED)
                .findFirst()
                .orElse(null);

        assertThat(rejectedEvent).isNotNull();
        assertThat(rejectedEvent.getPayload()).containsEntry("findingId", finding.getId().toString());
        assertThat(rejectedEvent.getPayload()).containsEntry("previousStatus", "CONFIRMED");
        assertThat(rejectedEvent.getPayload()).containsEntry("rejectionReason", "Verified protected by external cloud WAF rule.");
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("State Machine: Invalid transitions (REJECTED -> OPEN, FALSE_POSITIVE -> CONFIRMED, CONFIRMED -> OPEN) fail with 409 Conflict")
    void testInvalidStatusTransitions() throws Exception {
        // 1. Terminal REJECTED -> OPEN
        Finding rejectedFinding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Terminal Rejected Finding")
                .description("Rejected finding")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.REJECTED)
                .rejectionReason("Valid initial rejection")
                .build());

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + rejectedFinding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateFindingRequest(
                                null, null, null, null, FindingStatus.OPEN, null, null
                        ))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));

        // 2. Terminal FALSE_POSITIVE -> CONFIRMED
        Finding fpFinding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Terminal False Positive Finding")
                .description("FP finding")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.FALSE_POSITIVE)
                .build());

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + fpFinding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateFindingRequest(
                                null, null, null, null, FindingStatus.CONFIRMED, null, null
                        ))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));

        // 3. CONFIRMED -> OPEN
        Finding confirmedFinding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Confirmed Finding")
                .description("Confirmed finding")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .build());

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + confirmedFinding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateFindingRequest(
                                null, null, null, null, FindingStatus.OPEN, null, null
                        ))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Attach Evidence snippet (201 Created) and verify presence in GET /api/sessions/{id}/findings")
    void testAttachEvidenceSnippet() throws Exception {
        Finding finding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Evidence Linking Test")
                .description("Finding requiring proof snippet")
                .severity(FindingSeverity.HIGH)
                .confidence(FindingConfidence.FIRM)
                .status(FindingStatus.OPEN)
                .build());

        CreateEvidenceRequest evidenceRequest = new CreateEvidenceRequest(
                resultA.getId(),
                "Server: nginx/1.24.0\r\nMissing HSTS and CSP"
        );

        mockMvc.perform(post("/api/sessions/" + sessionA.getId() + "/findings/" + finding.getId() + "/evidence")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(evidenceRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.findingId").value(finding.getId().toString()))
                .andExpect(jsonPath("$.resultId").value(resultA.getId().toString()))
                .andExpect(jsonPath("$.executionId").value(executionA.getId().toString()))
                .andExpect(jsonPath("$.toolId").value("http_headers"))
                .andExpect(jsonPath("$.snippet").value("Server: nginx/1.24.0\r\nMissing HSTS and CSP"));

        // Verify loaded via GET /api/sessions/{id}/findings
        mockMvc.perform(get("/api/sessions/" + sessionA.getId() + "/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$[?(@.id == '" + finding.getId() + "')].evidence", hasSize(1)))
                .andExpect(jsonPath("$[?(@.id == '" + finding.getId() + "')].evidence[0].snippet")
                        .value("Server: nginx/1.24.0\r\nMissing HSTS and CSP"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("GET /api/sessions/{id}/report returns 200 OK text/html with session metadata, findings, and evidence")
    void testGetReportHtml() throws Exception {
        Finding finding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Confirmed XSS Vector")
                .description("Reflected parameters in error query")
                .severity(FindingSeverity.HIGH)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .remediation("Sanitize and encode all query parameters.")
                .build());

        evidenceRepository.save(Evidence.builder()
                .finding(finding)
                .result(resultA)
                .snippet("GET /search?q=<valid_token>")
                .build());

        MvcResult result = mockMvc.perform(get("/api/sessions/" + sessionA.getId() + "/report"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andReturn();

        String html = result.getResponse().getContentAsString();
        assertThat(html).contains("<!DOCTYPE html>");
        assertThat(html).contains(sessionA.getTargetUrl());
        assertThat(html).contains(sessionA.getScopeAckHash());
        assertThat(html).contains("Confirmed XSS Vector");
        assertThat(html).contains("Reflected parameters in error query");
        assertThat(html).contains("Sanitize and encode all query parameters.");
        assertThat(html).contains("GET /search?q=&lt;valid_token&gt;");
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Strict XSS Falsification Test: Malicious script tags in finding title, description, and snippet are escaped")
    void testXssFalsificationInHtmlReport() throws Exception {
        String xssPayload = "<script>alert('xss-exploit')</script><img src=x onerror=alert(1)>";

        Finding maliciousFinding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("XSS Injection: " + xssPayload)
                .description("Description payload: " + xssPayload)
                .severity(FindingSeverity.CRITICAL)
                .confidence(FindingConfidence.CERTAIN)
                .status(FindingStatus.CONFIRMED)
                .remediation("Remediation payload: " + xssPayload)
                .build());

        evidenceRepository.save(Evidence.builder()
                .finding(maliciousFinding)
                .result(resultA)
                .snippet("Evidence snippet payload: " + xssPayload)
                .build());

        MvcResult result = mockMvc.perform(get("/api/sessions/" + sessionA.getId() + "/report"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andReturn();

        String html = result.getResponse().getContentAsString();

        // Must escape opening and closing script tags
        assertThat(html).contains("&lt;script&gt;alert(&#39;xss-exploit&#39;)&lt;/script&gt;");
        assertThat(html).contains("&lt;img src=x onerror=alert(1)&gt;");

        // Falsification: Verify zero raw unescaped <script> tags exist in the report output
        assertThat(html).doesNotContain("<script>");
        assertThat(html).doesNotContain("</script>");
        assertThat(html).doesNotContain("<img src=x onerror=alert(1)>");
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Aborted Session Guard: Attempting to create finding, update finding, or attach evidence in ABORTED session returns 409 Conflict")
    void testAbortedSessionBlocksFindingCreationUpdateAndEvidenceAttachment() throws Exception {
        // Create an aborted session
        AuditSession abortedSession = auditSessionRepository.save(AuditSession.builder()
                .engagement(sessionA.getEngagement())
                .targetUrl("https://example.com/aborted")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ABORTED)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckHash("hash-aborted")
                .scopeAckTimestamp(Instant.now())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build());

        ToolExecution executionInAborted = toolExecutionRepository.save(ToolExecution.builder()
                .session(abortedSession)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .durationMs(100L)
                .createdAt(Instant.now())
                .startedAt(Instant.now())
                .endedAt(Instant.now())
                .build());

        ToolResult resultInAborted = toolResultRepository.save(ToolResult.builder()
                .execution(executionInAborted)
                .rawOutput("HTTP 200")
                .parsedData(Map.of())
                .hasErrors(false)
                .createdAt(Instant.now())
                .build());

        Finding findingInAborted = findingRepository.save(Finding.builder()
                .session(abortedSession)
                .title("Pre-existing finding")
                .description("Created before abort")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.OPEN)
                .build());

        // 1. Create finding in aborted session -> 409 Conflict
        CreateFindingRequest createReq = new CreateFindingRequest(
                null,
                "New Finding Attempt",
                "Should be blocked",
                FindingSeverity.HIGH,
                null,
                null
        );
        mockMvc.perform(post("/api/sessions/" + abortedSession.getId() + "/findings")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createReq)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));

        // 2. Update finding in aborted session -> 409 Conflict
        UpdateFindingRequest updateReq = new UpdateFindingRequest(
                "Updated Title", null, null, null, FindingStatus.CONFIRMED, null, null
        );
        mockMvc.perform(patch("/api/sessions/" + abortedSession.getId() + "/findings/" + findingInAborted.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));

        // 3. Attach evidence in aborted session -> 409 Conflict
        CreateEvidenceRequest evidenceReq = new CreateEvidenceRequest(
                resultInAborted.getId(),
                "Evidence snippet in aborted session"
        );
        mockMvc.perform(post("/api/sessions/" + abortedSession.getId() + "/findings/" + findingInAborted.getId() + "/evidence")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(evidenceReq)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("State Machine: OPEN -> FALSE_POSITIVE succeeds (200 OK) and decrements session active findingCount")
    void testOpenToFalsePositiveDecrementsActiveFindingCount() throws Exception {
        Finding finding = findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Potential False Positive")
                .description("Testing transition to FALSE_POSITIVE")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.OPEN)
                .build());

        // Verify active finding count in session is 1
        mockMvc.perform(get("/api/sessions/" + sessionA.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(1));

        UpdateFindingRequest request = new UpdateFindingRequest(
                null, null, null, null, FindingStatus.FALSE_POSITIVE, null, null
        );

        mockMvc.perform(patch("/api/sessions/" + sessionA.getId() + "/findings/" + finding.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("FALSE_POSITIVE"));

        // Verify active finding count decremented to 0
        mockMvc.perform(get("/api/sessions/" + sessionA.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findingCount").value(0));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Report Generation: Excluded findings (REJECTED and FALSE_POSITIVE) appear in Section 5 Appendix and are excluded from active findings")
    void testRejectedAndFalsePositiveAppendixInReportHtml() throws Exception {
        // Active finding
        findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Active Security Issue")
                .description("Legitimate open issue")
                .severity(FindingSeverity.HIGH)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .build());

        // Rejected finding with malicious HTML to verify escaping
        findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("Rejected Issue <script>alert('rejected')</script>")
                .description("Rejected description")
                .severity(FindingSeverity.MEDIUM)
                .confidence(FindingConfidence.FIRM)
                .status(FindingStatus.REJECTED)
                .rejectionReason("Protected by <WAF> rule")
                .build());

        // False positive finding
        findingRepository.save(Finding.builder()
                .session(sessionA)
                .title("False Positive Issue")
                .description("Heuristic flagged benign behavior")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.TENTATIVE)
                .status(FindingStatus.FALSE_POSITIVE)
                .build());

        MvcResult result = mockMvc.perform(get("/api/sessions/" + sessionA.getId() + "/report"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andReturn();

        String html = result.getResponse().getContentAsString();

        // Must have Section 5
        assertThat(html).contains("5. Rejected Findings &amp; False Positive Log (Appendix)");
        assertThat(html).contains("id=\"rejected-findings-appendix\"");

        // Must contain escaped titles and reasons
        assertThat(html).contains("Rejected Issue &lt;script&gt;alert(&#39;rejected&#39;)&lt;/script&gt;");
        assertThat(html).contains("Protected by &lt;WAF&gt; rule");
        assertThat(html).contains("False Positive Issue");
        assertThat(html).contains("Flagged as False Positive");

        // Falsification: Verify no raw script tags
        assertThat(html).doesNotContain("<script>alert('rejected')</script>");
    }
}
