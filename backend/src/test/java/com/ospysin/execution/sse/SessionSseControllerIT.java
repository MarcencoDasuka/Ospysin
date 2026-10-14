package com.ospysin.execution.sse;

import com.ospysin.AbstractIntegrationTest;
import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.engagements.EngagementStatus;
import com.ospysin.projects.Project;
import com.ospysin.projects.ProjectRepository;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.sessions.AuditSessionTxService;
import com.ospysin.sessions.SessionMode;
import com.ospysin.sessions.SessionState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.LocalDate;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
class SessionSseControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private EngagementRepository engagementRepository;

    @Autowired
    private AuditSessionRepository auditSessionRepository;

    @Autowired
    private Clock clock;

    private AuditSession activeSession;

    @BeforeEach
    void setUp() {
        Project project = projectRepository.findById(AuditSessionTxService.DEFAULT_PROJECT_ID).orElseThrow();
        Engagement engagement = engagementRepository.save(Engagement.builder()
                .project(project)
                .title("SSE Test Engagement " + UUID.randomUUID())
                .startDate(LocalDate.now(clock))
                .status(EngagementStatus.ACTIVE)
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

    @Test
    @DisplayName("GET /api/sessions/{id}/events without authentication returns 401 Unauthorized")
    void unauthenticatedRequestReturns401() throws Exception {
        mockMvc.perform(get("/api/sessions/" + activeSession.getId() + "/events"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("GET /api/sessions/{randomId}/events returns 404 Not Found ProblemDetail")
    void nonExistentSessionReturns404() throws Exception {
        UUID nonExistent = UUID.randomUUID();
        mockMvc.perform(get("/api/sessions/" + nonExistent + "/events"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("https://ospysin.dev/errors/resource-not-found"))
                .andExpect(jsonPath("$.detail").value(containsString("Session not found: " + nonExistent)));
    }

    @Test
    @WithMockUser(username = "auditor", roles = {"AUDITOR"})
    @DisplayName("GET /api/sessions/{id}/events with auditor credentials returns 200 OK and text/event-stream")
    void activeSessionReturns200TextEventStream() throws Exception {
        mockMvc.perform(get("/api/sessions/" + activeSession.getId() + "/events"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_EVENT_STREAM_VALUE));
    }
}
