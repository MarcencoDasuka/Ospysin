package com.ospysin.execution;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.AbstractIntegrationTest;
import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.engagements.EngagementStatus;
import com.ospysin.observations.ObservationRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.DnsResolver;
import com.ospysin.projects.Project;
import com.ospysin.projects.ProjectRepository;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.scope.ScopeAssetRepository;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.sessions.AuditSessionTxService;
import com.ospysin.sessions.SessionMode;
import com.ospysin.sessions.SessionState;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import com.ospysin.tools.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.InetAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class ToolExecutionQueueAndFencingIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private DnsResolver dnsResolver;

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
    private AuditEventRepository auditEventRepository;

    @Autowired
    private ToolExecutionTxService toolExecutionTxService;

    @Autowired
    private ToolExecutionWorker toolExecutionWorker;

    @Autowired
    private ExecutionWatchdog executionWatchdog;

    @Autowired
    private ToolCatalogRegistry toolCatalogRegistry;

    @Autowired
    private HostRateLimiter hostRateLimiter;

    @Autowired
    private AuditSessionTxService auditSessionTxService;

    @Autowired
    private Clock clock;

    @Autowired(required = false)
    private com.ospysin.tools.probes.HttpHeadersTool realHttpHeadersTool;

    private AuditSession activeSession;

    @BeforeEach
    void setUp() throws Exception {
        hostRateLimiter.reset();
        toolExecutionWorker.setAutoDispatchEnabled(false);
        toolExecutionWorker.setAutoAdvisoryEnabled(false);

        when(dnsResolver.resolveAll("example.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("93.184.216.34")});

        // Register deterministic test stub for http_headers tool
        toolCatalogRegistry.registerToolBean(new OspysinTool() {
            @Override
            public String getToolId() {
                return "http_headers";
            }

            @Override
            public void validateParams(Map<String, Object> params) {}

            @Override
            public ToolExecutionOutcome execute(ToolExecutionContext context) {
                return new ToolExecutionOutcome(
                        "HTTP/1.1 200 OK\r\nServer: nginx\r\nStrict-Transport-Security: max-age=31536000",
                        Map.of("statusCode", 200, "server", "nginx"),
                        90,
                        false,
                        List.of(
                                new ObservationDraft("HTTP", "Server banner exposed: nginx", SeverityHeuristic.INFO),
                                new ObservationDraft("SECURITY", "HSTS header present", SeverityHeuristic.LOW)
                        )
                );
            }
        });

        // Provision active test session
        Project project = projectRepository.findById(AuditSessionTxService.DEFAULT_PROJECT_ID).orElseThrow();
        Engagement engagement = engagementRepository.save(Engagement.builder()
                .project(project)
                .title("Test Engagement " + UUID.randomUUID())
                .startDate(LocalDate.now(clock))
                .status(EngagementStatus.ACTIVE)
                .createdAt(clock.instant())
                .build());

        scopeAssetRepository.save(ScopeAsset.builder()
                .engagement(engagement)
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(false)
                .createdAt(clock.instant())
                .build());

        activeSession = auditSessionRepository.save(AuditSession.builder()
                .engagement(engagement)
                .targetUrl("https://example.com")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckText("Authorization")
                .scopeAckHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .scopeAckTimestamp(clock.instant())
                .createdAt(clock.instant())
                .updatedAt(clock.instant())
                .build());
    }

    @AfterEach
    void tearDown() {
        hostRateLimiter.reset();
        toolExecutionWorker.setAutoDispatchEnabled(false);
        toolExecutionWorker.setAutoAdvisoryEnabled(false);
        if (realHttpHeadersTool != null) {
            toolCatalogRegistry.registerToolBean(realHttpHeadersTool);
        }
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Asynchronous Acceptance & Lifecycle: enqueue returns 202 Accepted, worker executes, results & observations persisted")
    void asyncAcceptanceAndLifecycle() throws Exception {
        toolExecutionWorker.setAutoDispatchEnabled(true);
        try {
            Map<String, Object> params = Map.of("customPort", 8080, "followRedirects", true);

        MvcResult mvcResult = mockMvc.perform(post("/api/sessions/" + activeSession.getId() + "/tools/http_headers/run")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(params)))
                .andExpect(status().isAccepted())
                .andExpect(header().string(HttpHeaders.LOCATION, containsString("/api/sessions/" + activeSession.getId() + "/steps/")))
                .andExpect(jsonPath("$.executionId").isNotEmpty())
                .andExpect(jsonPath("$.sessionId").value(activeSession.getId().toString()))
                .andExpect(jsonPath("$.toolId").value("http_headers"))
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn();

        String responseBody = mvcResult.getResponse().getContentAsString();
        UUID executionId = UUID.fromString(objectMapper.readTree(responseBody).get("executionId").asText());

        // Bounded polling up to 5 seconds until background worker completes execution
        long deadline = System.currentTimeMillis() + 5000;
        ToolExecution execution = null;
        while (System.currentTimeMillis() < deadline) {
            Optional<ToolExecution> execOpt = toolExecutionRepository.findById(executionId);
            if (execOpt.isPresent() && execOpt.get().getStatus() == ExecutionStatus.COMPLETED) {
                execution = execOpt.get();
                break;
            }
            Thread.sleep(50);
        }

        // Verify state in PostgreSQL
        assertThat(execution).isNotNull();
        assertThat(execution.getStatus()).isEqualTo(ExecutionStatus.COMPLETED);
        assertThat(execution.getDurationMs()).isNotNull();
        assertThat(execution.getLeaseEpoch()).isEqualTo(1);
        assertThat(execution.getStartedAt()).isNotNull();
        assertThat(execution.getEndedAt()).isNotNull();

        // Verify ToolResult in PostgreSQL
        ToolResult result = toolResultRepository.findByExecutionId(executionId).orElseThrow();
        assertThat(result.getRawOutput()).contains("Server: nginx");
        assertThat(result.getScore()).isEqualTo(90);
        assertThat(result.isHasErrors()).isFalse();

        // Verify Observations in PostgreSQL
        var observations = observationRepository.findByResultId(result.getId());
        assertThat(observations).hasSize(2);
        assertThat(observations).extracting(obs -> obs.getCategory()).contains("HTTP", "SECURITY");

        // Verify POLICY_EVALUATED and lifecycle audit events in PostgreSQL
        List<AuditEvent> auditEvents = auditEventRepository.findBySessionIdOrderByTimestampAsc(activeSession.getId());
        assertThat(auditEvents).extracting(AuditEvent::getEventType)
                .contains(AuditEventType.TOOL_TRIGGERED, AuditEventType.POLICY_EVALUATED, AuditEventType.TOOL_FINISHED);

        // Verify GET /api/sessions/{id}/steps
        mockMvc.perform(get("/api/sessions/" + activeSession.getId() + "/steps"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].executionId").value(executionId.toString()))
                .andExpect(jsonPath("$[0].toolId").value("http_headers"))
                .andExpect(jsonPath("$[0].status").value("COMPLETED"))
                .andExpect(jsonPath("$[0].observationCount").value(2));

        // Verify GET /api/sessions/{id}/steps/{stepId}
        mockMvc.perform(get("/api/sessions/" + activeSession.getId() + "/steps/" + executionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.executionId").value(executionId.toString()))
                .andExpect(jsonPath("$.toolId").value("http_headers"))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.score").value(90))
                .andExpect(jsonPath("$.rawOutput").value(containsString("Server: nginx")))
                .andExpect(jsonPath("$.observations", hasSize(2)));
        } finally {
            toolExecutionWorker.setAutoDispatchEnabled(false);
        }
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("BOLA Guard on Step Detail: requesting step belonging to session A from session B returns 404")
    void bolaGuardOnStepDetail() throws Exception {
        toolExecutionWorker.setAutoDispatchEnabled(false);
        ToolExecution executionA = toolExecutionTxService.enqueueExecution(activeSession.getId(), "http_headers", Map.of());

        // Create second session B
        AuditSession sessionB = auditSessionRepository.save(AuditSession.builder()
                .engagement(activeSession.getEngagement())
                .targetUrl("https://other-example.com")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckText("Auth")
                .scopeAckHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .scopeAckTimestamp(clock.instant())
                .createdAt(clock.instant())
                .updatedAt(clock.instant())
                .build());

        // Access executionA via sessionB -> 404
        mockMvc.perform(get("/api/sessions/" + sessionB.getId() + "/steps/" + executionA.getId()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/resource-not-found"));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Duplicate Active Execution Guard: triggering second tool while an execution is PENDING or RUNNING returns 409 Conflict")
    void duplicateActiveExecutionGuard() throws Exception {
        toolExecutionWorker.setAutoDispatchEnabled(false);
        // Enqueue first execution (it stays PENDING)
        toolExecutionTxService.enqueueExecution(activeSession.getId(), "http_headers", Map.of());

        // Attempting to enqueue second execution while first is PENDING -> 409 Conflict
        mockMvc.perform(post("/api/sessions/" + activeSession.getId() + "/tools/dns_lookup/run")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/conflict"))
                .andExpect(jsonPath("$.detail").value(containsString("already PENDING or RUNNING")));
    }

    @Test
    @DisplayName("Epoch Fencing Invariant: stale worker output is rejected and 0 tool_results rows exist when epoch is bumped")
    void epochFencingInvariantRejectsStaleWorker() {
        // Seed PENDING execution directly so we can simulate deterministic worker claim
        ToolExecution execution = toolExecutionRepository.save(ToolExecution.builder()
                .session(activeSession)
                .toolId("http_headers")
                .status(ExecutionStatus.PENDING)
                .inputParams(Map.of())
                .leaseEpoch(0)
                .attempts(0)
                .createdAt(clock.instant())
                .build());
        UUID executionId = execution.getId();

        // Worker 1 claims task at lease_epoch = 1
        UUID worker1Id = UUID.randomUUID();
        ClaimedExecution claimed = toolExecutionTxService.claimExecution(executionId, worker1Id).orElseThrow();
        assertThat(claimed.claimedEpoch()).isEqualTo(1);

        // Abort session while worker 1 is running -> bumps lease_epoch to 2 and marks CANCELLED
        auditSessionTxService.abortSession(activeSession.getId());

        ToolExecution abortedExecution = toolExecutionRepository.findById(executionId).orElseThrow();
        assertThat(abortedExecution.getLeaseEpoch()).isEqualTo(2);
        assertThat(abortedExecution.getStatus()).isEqualTo(ExecutionStatus.CANCELLED);

        // Stale worker 1 attempts Phase 3 persistence with stale claimedEpoch = 1
        ToolExecutionOutcome outcome = new ToolExecutionOutcome(
                "stale output",
                Map.of("key", "val"),
                100,
                false,
                List.of(new ObservationDraft("STALE", "stale observation", SeverityHeuristic.HIGH))
        );

        boolean persisted = toolExecutionTxService.persistSuccess(executionId, 1, outcome, claimed.startedAt());
        assertThat(persisted).isFalse();

        // Invariant: exactly 0 tool_results rows exist for this execution
        assertThat(toolResultRepository.findByExecutionId(executionId)).isEmpty();
    }

    @Test
    @DisplayName("Watchdog Expiration Test: reclaims expired lease, transitions to FAILED, increments lease_epoch")
    void watchdogReclaimsExpiredLease() {
        Instant past = clock.instant().minusSeconds(120);
        ToolExecution execution = toolExecutionRepository.save(ToolExecution.builder()
                .session(activeSession)
                .toolId("http_headers")
                .status(ExecutionStatus.RUNNING)
                .inputParams(Map.of())
                .leaseOwner(UUID.randomUUID())
                .leaseEpoch(1)
                .leaseExpiresAt(past)
                .attempts(1)
                .createdAt(past.minusSeconds(30))
                .startedAt(past)
                .build());

        int reclaimed = executionWatchdog.reclaimExpiredLeases();
        assertThat(reclaimed).isGreaterThanOrEqualTo(1);

        ToolExecution updated = toolExecutionRepository.findById(execution.getId()).orElseThrow();
        assertThat(updated.getStatus()).isEqualTo(ExecutionStatus.FAILED);
        assertThat(updated.getFailureReason()).isEqualTo("LEASE_EXPIRED");
        assertThat(updated.getLeaseEpoch()).isEqualTo(2);
        assertThat(updated.getEndedAt()).isNotNull();
    }

    @Test
    @DisplayName("drainPendingQueue: claims and executes orphaned PENDING task using FOR UPDATE SKIP LOCKED")
    void drainPendingQueueClaimsAndExecutesPendingTask() {
        toolExecutionWorker.setAutoDispatchEnabled(false);
        ToolExecution execution = toolExecutionTxService.enqueueExecution(activeSession.getId(), "http_headers", Map.of());
        assertThat(execution.getStatus()).isEqualTo(ExecutionStatus.PENDING);

        int drained = toolExecutionWorker.drainPendingQueue();
        assertThat(drained).isEqualTo(1);

        ToolExecution completed = toolExecutionRepository.findById(execution.getId()).orElseThrow();
        assertThat(completed.getStatus()).isEqualTo(ExecutionStatus.COMPLETED);
        assertThat(completed.getLeaseEpoch()).isEqualTo(1);
    }

    @Test
    @DisplayName("Policy denial records POLICY_EVALUATED event and transitions task to FAILED")
    void policyDenialRecordsAuditEventAndFails() throws Exception {
        when(dnsResolver.resolveAll("private.example.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("127.0.0.1")});

        AuditSession privateSession = auditSessionRepository.save(AuditSession.builder()
                .engagement(activeSession.getEngagement())
                .targetUrl("https://private.example.com")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckText("Authorization")
                .scopeAckHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .scopeAckTimestamp(clock.instant())
                .createdAt(clock.instant())
                .updatedAt(clock.instant())
                .build());

        hostRateLimiter.reset();
        ToolExecution execution = toolExecutionTxService.enqueueExecution(privateSession.getId(), "http_headers", Map.of());
        toolExecutionWorker.executeTask(execution.getId());

        ToolExecution failed = toolExecutionRepository.findById(execution.getId()).orElseThrow();
        assertThat(failed.getStatus()).isEqualTo(ExecutionStatus.FAILED);
        assertThat(failed.getFailureReason()).isEqualTo("POLICY_DENIED");

        List<AuditEvent> auditEvents = auditEventRepository.findBySessionIdOrderByTimestampAsc(privateSession.getId());
        assertThat(auditEvents).extracting(AuditEvent::getEventType)
                .contains(AuditEventType.POLICY_EVALUATED, AuditEventType.TOOL_FINISHED);
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Validation failure on unknown tool returns 400 Bad Request ProblemDetail")
    void unknownToolReturns400() throws Exception {
        mockMvc.perform(post("/api/sessions/" + activeSession.getId() + "/tools/unknown_exploit_tool/run")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/bad-request"))
                .andExpect(jsonPath("$.detail").value(containsString("Unknown tool ID")));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("Validation failure on invalid parameter returns 422 Unprocessable Entity with invalidParams")
    void invalidParamReturns422() throws Exception {
        mockMvc.perform(post("/api/sessions/" + activeSession.getId() + "/tools/http_headers/run")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("customPort", 99999))))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/validation-error"))
                .andExpect(jsonPath("$.invalidParams", hasSize(1)))
                .andExpect(jsonPath("$.invalidParams[0].name").value("customPort"));
    }

    @Test
    @DisplayName("All 15 canonical tools in ToolCatalogRegistry resolve to active OspysinTool beans")
    void all15CanonicalToolsResolveToBeans() {
        List<ToolMetadata> allTools = toolCatalogRegistry.getAllTools();
        assertThat(allTools).hasSize(15);
        for (ToolMetadata metadata : allTools) {
            assertThat(toolCatalogRegistry.getTool(metadata.id()))
                    .as("Tool bean for '%s' must be present in registry", metadata.id())
                    .isPresent();
        }
    }
}
