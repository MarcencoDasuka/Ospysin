package com.ospysin.tools.analysis;

import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.ResourceNotFoundException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class SecurityHeadersScoreToolTest {

    private ToolExecutionRepository toolExecutionRepository;
    private ToolResultRepository toolResultRepository;
    private SecurityHeadersScoreTool tool;

    private UUID currentSessionId;
    private UUID otherSessionId;
    private AuditSession currentSession;
    private AuditSession otherSession;

    @BeforeEach
    void setUp() {
        toolExecutionRepository = mock(ToolExecutionRepository.class);
        toolResultRepository = mock(ToolResultRepository.class);
        tool = new SecurityHeadersScoreTool(toolExecutionRepository, toolResultRepository);

        currentSessionId = UUID.randomUUID();
        otherSessionId = UUID.randomUUID();

        currentSession = mock(AuditSession.class);
        when(currentSession.getId()).thenReturn(currentSessionId);

        otherSession = mock(AuditSession.class);
        when(otherSession.getId()).thenReturn(otherSessionId);
    }

    @Test
    @DisplayName("Perfect score (100/100, Grade A) when all 6 OWASP security headers are present and properly configured")
    void perfectScoreWhenAllHeadersConfigured() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        Map<String, Object> headers = Map.of(
                "strict-transport-security", "max-age=31536000; includeSubDomains; preload",
                "content-security-policy", "default-src 'self'; script-src 'self'",
                "x-content-type-options", "nosniff",
                "x-frame-options", "DENY",
                "referrer-policy", "strict-origin-when-cross-origin",
                "permissions-policy", "geolocation=(), microphone=()"
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("HTTP/1.1 200 OK")
                .parsedData(Map.of("headers", headers))
                .build();

        when(toolExecutionRepository.findById(stepId)).thenReturn(Optional.of(execution));
        when(toolResultRepository.findByExecutionId(stepId)).thenReturn(Optional.of(result));

        ToolExecutionContext context = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", stepId.toString()),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.score()).isEqualTo(100);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("score")).isEqualTo(100);
        assertThat(data.get("grade")).isEqualTo("A");
        assertThat(data.get("evaluatedStepId")).isEqualTo(stepId.toString());

        @SuppressWarnings("unchecked")
        List<String> missing = (List<String>) data.get("missingHeaders");
        assertThat(missing).isEmpty();

        @SuppressWarnings("unchecked")
        List<String> present = (List<String>) data.get("presentHeaders");
        assertThat(present).containsExactlyInAnyOrder(
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy"
        );

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        ObservationDraft obs = observations.get(0);
        assertThat(obs.category()).isEqualTo("SECURITY_SCORE");
        assertThat(obs.severityHeuristic()).isEqualTo(SeverityHeuristic.INFO);
        assertThat(obs.description()).contains("Strong HTTP security header posture: score 100/100 (Grade A)");
    }

    @Test
    @DisplayName("Partial score (65/100, Grade C) when CSP and Permissions-Policy are missing")
    void partialScoreWhenCspAndPermissionsPolicyMissing() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        Map<String, Object> headers = Map.of(
                "strict-transport-security", "max-age=15768000; includeSubDomains", // 25 pts
                "x-content-type-options", "nosniff",                                 // 15 pts
                "x-frame-options", "SAMEORIGIN",                                     // 15 pts
                "referrer-policy", "no-referrer"                                     // 10 pts
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("HTTP/1.1 200 OK")
                .parsedData(Map.of("headers", headers))
                .build();

        when(toolExecutionRepository.findById(stepId)).thenReturn(Optional.of(execution));
        when(toolResultRepository.findByExecutionId(stepId)).thenReturn(Optional.of(result));

        ToolExecutionContext context = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", stepId.toString()),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.score()).isEqualTo(65);
        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("grade")).isEqualTo("C");

        @SuppressWarnings("unchecked")
        List<String> missing = (List<String>) data.get("missingHeaders");
        assertThat(missing).containsExactlyInAnyOrder("Content-Security-Policy", "Permissions-Policy");

        @SuppressWarnings("unchecked")
        List<String> recs = (List<String>) data.get("recommendations");
        assertThat(recs).anyMatch(r -> r.contains("Content-Security-Policy"));
        assertThat(recs).anyMatch(r -> r.contains("Permissions-Policy"));

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
        assertThat(observations.get(0).description()).contains("Moderate HTTP security header posture: score 65/100 (Grade C)");
    }

    @Test
    @DisplayName("Weak score (<50, Grade F) with weak HSTS and unsafe-inline CSP awards partial points and High severity observation")
    void weakScoreWithShortHstsAndUnsafeCsp() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        Map<String, Object> headers = Map.of(
                "strict-transport-security", "max-age=3600",                          // 15 pts (weak)
                "content-security-policy", "default-src 'self' 'unsafe-inline'"       // 15 pts (unsafe)
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("HTTP/1.1 200 OK")
                .parsedData(Map.of("headers", headers))
                .build();

        when(toolExecutionRepository.findById(stepId)).thenReturn(Optional.of(execution));
        when(toolResultRepository.findByExecutionId(stepId)).thenReturn(Optional.of(result));

        ToolExecutionContext context = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", stepId.toString()),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.score()).isEqualTo(30);
        assertThat(outcome.parsedData().get("grade")).isEqualTo("F");

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);
        assertThat(observations.get(0).description()).contains("Weak HTTP security header posture: score 30/100 (Grade F)");
    }

    @Test
    @DisplayName("CSP frame-ancestors satisfies clickjacking requirement even if X-Frame-Options is omitted")
    void cspFrameAncestorsSatisfiesFrameProtection() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        Map<String, Object> headers = Map.of(
                "content-security-policy", "default-src 'self'; frame-ancestors 'none'"
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("HTTP/1.1 200 OK")
                .parsedData(Map.of("headers", headers))
                .build();

        when(toolExecutionRepository.findById(stepId)).thenReturn(Optional.of(execution));
        when(toolResultRepository.findByExecutionId(stepId)).thenReturn(Optional.of(result));

        ToolExecutionContext context = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", stepId.toString()),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);

        @SuppressWarnings("unchecked")
        List<String> present = (List<String>) outcome.parsedData().get("presentHeaders");
        assertThat(present).contains("X-Frame-Options");
    }

    @Test
    @DisplayName("BOLA Guard: Referencing a step belonging to another session throws ResourceNotFoundException (preventing IDOR)")
    void bolaGuardRejectsCrossSessionStepReference() {
        UUID stepId = UUID.randomUUID();
        ToolExecution foreignExecution = ToolExecution.builder()
                .session(otherSession) // Belongs to otherSession!
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        when(toolExecutionRepository.findById(stepId)).thenReturn(Optional.of(foreignExecution));

        ToolExecutionContext context = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", stepId.toString()),
                null
        );

        assertThatThrownBy(() -> tool.execute(context))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Step not found: " + stepId);
    }

    @Test
    @DisplayName("Prerequisite guard: Referencing a non-completed or wrong-tool step throws ValidationException")
    void prerequisiteGuardRejectsIncompleteOrWrongToolStep() {
        UUID runningStepId = UUID.randomUUID();
        ToolExecution runningExecution = ToolExecution.builder()
                .session(currentSession)
                .toolId("http_headers")
                .status(ExecutionStatus.RUNNING) // Not COMPLETED!
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();
        when(toolExecutionRepository.findById(runningStepId)).thenReturn(Optional.of(runningExecution));

        ToolExecutionContext runningContext = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", runningStepId.toString()),
                null
        );

        assertThatThrownBy(() -> tool.execute(runningContext))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("stepId");
                    assertThat(ve.getInvalidParams().get(0).reason()).contains("completed http_headers execution");
                });

        UUID wrongToolStepId = UUID.randomUUID();
        ToolExecution wrongToolExecution = ToolExecution.builder()
                .session(currentSession)
                .toolId("tech_detect") // Wrong tool!
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();
        when(toolExecutionRepository.findById(wrongToolStepId)).thenReturn(Optional.of(wrongToolExecution));

        ToolExecutionContext wrongToolContext = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", wrongToolStepId.toString()),
                null
        );

        assertThatThrownBy(() -> tool.execute(wrongToolContext))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams rejects missing, blank, or malformed stepId")
    void validateParamsRejectsInvalidStepId() {
        assertThatThrownBy(() -> tool.validateParams(null))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of()))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("stepId", "   ")))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("stepId", "not-a-uuid")))
                .isInstanceOf(ValidationException.class);

        // Valid UUID accepted
        tool.validateParams(Map.of("stepId", UUID.randomUUID().toString()));
    }
}
