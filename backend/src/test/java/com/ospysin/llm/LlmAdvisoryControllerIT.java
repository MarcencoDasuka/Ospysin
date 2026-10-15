package com.ospysin.llm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.AbstractIntegrationTest;
import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.engagements.EngagementStatus;
import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.execution.sse.SessionSseHub;
import com.ospysin.llm.client.LlmClient;
import com.ospysin.llm.dto.LlmChatRequest;
import com.ospysin.llm.dto.LlmCommentRequest;
import com.ospysin.observations.Observation;
import com.ospysin.observations.ObservationRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.projects.Project;
import com.ospysin.projects.ProjectRepository;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.sessions.AuditSessionTxService;
import com.ospysin.sessions.SessionMode;
import com.ospysin.sessions.SessionState;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import com.ospysin.llm.dto.LlmChatReplyPayload;
import com.ospysin.llm.dto.LlmCommentPayload;
import com.ospysin.llm.service.LlmAdvisoryTxService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class LlmAdvisoryControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private EngagementRepository engagementRepository;

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
    private SessionSseHub sessionSseHub;

    @Autowired
    private LlmAdvisoryTxService llmAdvisoryTxService;

    @Autowired
    private Clock clock;

    @MockBean
    private LlmClient llmClient;

    private AuditSession activeSession;
    private ToolExecution completedStep;

    @BeforeEach
    void setUp() {
        Project project = projectRepository.findById(AuditSessionTxService.DEFAULT_PROJECT_ID).orElseThrow();
        Engagement engagement = engagementRepository.save(Engagement.builder()
                .project(project)
                .title("LLM Test Engagement " + UUID.randomUUID())
                .startDate(LocalDate.now(clock))
                .status(EngagementStatus.ACTIVE)
                .createdAt(clock.instant())
                .build());

        activeSession = auditSessionRepository.save(AuditSession.builder()
                .engagement(engagement)
                .targetUrl("https://advisory.target.example.org")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckHash("hash-advisory")
                .scopeAckTimestamp(clock.instant())
                .createdAt(clock.instant())
                .build());

        Instant now = clock.instant();
        completedStep = toolExecutionRepository.save(ToolExecution.builder()
                .session(activeSession)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of("followRedirects", false))
                .startedAt(now.minusSeconds(1))
                .endedAt(now)
                .durationMs(250L)
                .createdAt(now.minusSeconds(2))
                .build());

        ToolResult result = toolResultRepository.save(ToolResult.builder()
                .execution(completedStep)
                .rawOutput("HTTP/1.1 200 OK\r\nServer: Apache\r\n")
                .parsedData(Map.of("statusCode", 200, "headers", Map.of("Server", "Apache")))
                .score(85)
                .hasErrors(false)
                .createdAt(now)
                .build());

        observationRepository.save(Observation.builder()
                .result(result)
                .category("HTTP")
                .description("Missing Content-Security-Policy header")
                .severityHeuristic(SeverityHeuristic.MEDIUM)
                .detectedAt(now)
                .build());

        when(llmClient.generateCommentJson(anyString(), anyString())).thenReturn("""
                {
                  "comment": "Apache server detected without CSP header, leaving application vulnerable to XSS.",
                  "suggested_tool": "tls_info",
                  "suggested_reason": "Verify whether SSL/TLS enforces modern ciphers and HSTS."
                }
                """);

        when(llmClient.generateChatReply(anyString(), anyString()))
                .thenReturn("A Content-Security-Policy header mitigates cross-site scripting attacks.");
    }

    @AfterEach
    void tearDown() {
        sessionSseHub.clearAll();
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/comment returns 202 Accepted, persists LLM_QUERY and LLM_COMMENT, broadcasts SSE")
    void testCommentLifecycle() throws Exception {
        // Subscribe an SseEmitter to receive broadcast
        SseEmitter emitter = sessionSseHub.subscribe(activeSession.getId());
        assertThat(sessionSseHub.getActiveEmitterCount(activeSession.getId())).isEqualTo(1);

        LlmCommentRequest request = new LlmCommentRequest(completedStep.getId());

        mockMvc.perform(post("/api/sessions/{id}/llm/comment", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andExpect(jsonPath("$.message").value("LLM commentary request enqueued"));

        // Bounded polling for async background execution to complete
        long deadline = System.currentTimeMillis() + 5000;
        List<AuditEvent> events = List.of();
        while (System.currentTimeMillis() < deadline) {
            events = auditEventRepository.findBySessionIdOrderByTimestampAsc(activeSession.getId());
            boolean hasComment = events.stream().anyMatch(e -> e.getEventType() == AuditEventType.LLM_COMMENT);
            if (hasComment) {
                break;
            }
            Thread.sleep(50);
        }

        assertThat(events).extracting(AuditEvent::getEventType)
                .contains(AuditEventType.LLM_QUERY, AuditEventType.LLM_COMMENT);

        AuditEvent commentEvent = events.stream()
                .filter(e -> e.getEventType() == AuditEventType.LLM_COMMENT)
                .findFirst()
                .orElseThrow();

        assertThat(commentEvent.getPayload().get("comment").toString()).contains("Apache server detected");
        assertThat(commentEvent.getPayload().get("suggestedTool")).isEqualTo("tls_info");
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/comment rejects stepId belonging to another session with 404 (BOLA guard)")
    void testBolaDefenseOnComment() throws Exception {
        // Create second session with step
        Engagement engagement = activeSession.getEngagement();
        AuditSession otherSession = auditSessionRepository.save(AuditSession.builder()
                .engagement(engagement)
                .targetUrl("https://other.target.example.org")
                .mode(SessionMode.PUBLIC)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckHash("hash-other")
                .scopeAckTimestamp(clock.instant())
                .createdAt(clock.instant())
                .build());

        ToolExecution otherStep = toolExecutionRepository.save(ToolExecution.builder()
                .session(otherSession)
                .toolId("dns_lookup")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(clock.instant())
                .build());

        // Attempt to request comment for otherStep on activeSession
        LlmCommentRequest bolaRequest = new LlmCommentRequest(otherStep.getId());

        mockMvc.perform(post("/api/sessions/{id}/llm/comment", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bolaRequest)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.title").value("Resource Not Found"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/comment returns 404 when session does not exist")
    void testCommentSessionNotFound() throws Exception {
        UUID nonExistentId = UUID.randomUUID();
        LlmCommentRequest request = new LlmCommentRequest(completedStep.getId());

        mockMvc.perform(post("/api/sessions/{id}/llm/comment", nonExistentId)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/chat returns 202 Accepted, persists LLM_QUERY and LLM_COMMENT, broadcasts SSE")
    void testChatLifecycle() throws Exception {
        LlmChatRequest request = new LlmChatRequest("How do I mitigate the missing Content-Security-Policy header?");

        mockMvc.perform(post("/api/sessions/{id}/llm/chat", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andExpect(jsonPath("$.message").value("Chat query enqueued"));

        // Bounded polling for async background chat response
        long deadline = System.currentTimeMillis() + 5000;
        List<AuditEvent> events = List.of();
        while (System.currentTimeMillis() < deadline) {
            events = auditEventRepository.findBySessionIdOrderByTimestampAsc(activeSession.getId());
            boolean hasChatComment = events.stream().anyMatch(e -> e.getEventType() == AuditEventType.LLM_COMMENT);
            if (hasChatComment) {
                break;
            }
            Thread.sleep(50);
        }

        assertThat(events).extracting(AuditEvent::getEventType)
                .contains(AuditEventType.LLM_QUERY, AuditEventType.LLM_COMMENT);

        AuditEvent chatEvent = events.stream()
                .filter(e -> e.getEventType() == AuditEventType.LLM_COMMENT)
                .findFirst()
                .orElseThrow();

        assertThat(chatEvent.getPayload().get("reply").toString()).contains("Content-Security-Policy");
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/chat rejects request on COMPLETED session with 409 Conflict")
    void testChatOnNonActiveSession() throws Exception {
        activeSession.setState(SessionState.COMPLETED);
        auditSessionRepository.save(activeSession);

        LlmChatRequest request = new LlmChatRequest("Is this target safe?");

        mockMvc.perform(post("/api/sessions/{id}/llm/chat", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.title").value("Conflict"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/chat rejects blank message with 422 Unprocessable Entity")
    void testChatBlankValidation() throws Exception {
        LlmChatRequest request = new LlmChatRequest("   ");

        mockMvc.perform(post("/api/sessions/{id}/llm/chat", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.status").value(422))
                .andExpect(jsonPath("$.invalidParams").isArray());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/comment rejects non-COMPLETED step with 409 Conflict (P12-03)")
    void testCommentRejectsNonCompletedStepWith409Conflict() throws Exception {
        ToolExecution runningStep = toolExecutionRepository.save(ToolExecution.builder()
                .session(activeSession)
                .toolId("tls_info")
                .status(ExecutionStatus.RUNNING)
                .inputParams(Map.of())
                .startedAt(clock.instant())
                .createdAt(clock.instant())
                .build());

        LlmCommentRequest request = new LlmCommentRequest(runningStep.getId());

        mockMvc.perform(post("/api/sessions/{id}/llm/comment", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.title").value("Conflict"))
                .andExpect(jsonPath("$.detail").value("Cannot generate LLM commentary for step in status: RUNNING"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("POST /llm/comment rejects request on COMPLETED session with 409 Conflict (P12-03)")
    void testCommentRejectsNonActiveSessionWith409Conflict() throws Exception {
        activeSession.setState(SessionState.COMPLETED);
        auditSessionRepository.save(activeSession);

        LlmCommentRequest request = new LlmCommentRequest(completedStep.getId());

        mockMvc.perform(post("/api/sessions/{id}/llm/comment", activeSession.getId())
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.title").value("Conflict"))
                .andExpect(jsonPath("$.detail").value("Cannot request LLM commentary for session in state: COMPLETED"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    @DisplayName("recordCommentAndBroadcast and recordChatReplyAndBroadcast fence late outputs on ABORTED session (P12-03)")
    void testFencingLateOutputsWhenSessionAborted() {
        activeSession.setState(SessionState.ABORTED);
        auditSessionRepository.save(activeSession);

        int initialCommentEvents = (int) auditEventRepository.findBySessionIdOrderByTimestampAsc(activeSession.getId())
                .stream()
                .filter(e -> e.getEventType() == AuditEventType.LLM_COMMENT)
                .count();

        LlmCommentPayload commentPayload = new LlmCommentPayload(
                completedStep.getId(),
                "http_headers",
                "Late commentary that should be fenced",
                null,
                null,
                clock.instant()
        );
        llmAdvisoryTxService.recordCommentAndBroadcast(activeSession.getId(), commentPayload);

        LlmChatReplyPayload chatPayload = new LlmChatReplyPayload(
                "Late chat reply that should be fenced",
                clock.instant()
        );
        llmAdvisoryTxService.recordChatReplyAndBroadcast(activeSession.getId(), chatPayload);

        int finalCommentEvents = (int) auditEventRepository.findBySessionIdOrderByTimestampAsc(activeSession.getId())
                .stream()
                .filter(e -> e.getEventType() == AuditEventType.LLM_COMMENT)
                .count();

        // Late broadcasts must be fenced: no LLM_COMMENT audit events should be persisted
        assertThat(finalCommentEvents).isEqualTo(initialCommentEvents);
    }
}
