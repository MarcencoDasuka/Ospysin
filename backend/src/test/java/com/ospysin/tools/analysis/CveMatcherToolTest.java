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

class CveMatcherToolTest {

    private ToolExecutionRepository toolExecutionRepository;
    private ToolResultRepository toolResultRepository;
    private CveMatcherTool tool;

    private UUID currentSessionId;
    private UUID otherSessionId;
    private AuditSession currentSession;
    private AuditSession otherSession;

    @BeforeEach
    void setUp() {
        toolExecutionRepository = mock(ToolExecutionRepository.class);
        toolResultRepository = mock(ToolResultRepository.class);
        tool = new CveMatcherTool(toolExecutionRepository, toolResultRepository);

        currentSessionId = UUID.randomUUID();
        otherSessionId = UUID.randomUUID();

        currentSession = mock(AuditSession.class);
        when(currentSession.getId()).thenReturn(currentSessionId);

        otherSession = mock(AuditSession.class);
        when(otherSession.getId()).thenReturn(otherSessionId);
    }

    @Test
    @DisplayName("Matches Apache HTTP Server 2.4.49 against known CVEs (CVE-2021-41773, CVE-2021-42013, CVE-2023-25690)")
    void matchesApacheVulnerabilities() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("tech_detect")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        List<Map<String, Object>> technologies = List.of(
                Map.of("name", "Apache HTTP Server", "version", "2.4.49", "category", "Web Server", "confidence", "CONFIRMED")
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("Apache/2.4.49 detected")
                .parsedData(Map.of("technologies", technologies))
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

        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("matchedCount")).isEqualTo(3);
        assertThat(data.get("evaluatedStepId")).isEqualTo(stepId.toString());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> vulns = (List<Map<String, Object>>) data.get("vulnerabilities");
        assertThat(vulns).hasSize(3);

        List<String> cveIds = vulns.stream().map(v -> (String) v.get("cveId")).toList();
        assertThat(cveIds).containsExactlyInAnyOrder("CVE-2021-41773", "CVE-2021-42013", "CVE-2023-25690");

        // Verify public exploit status & CVSS scores
        for (Map<String, Object> v : vulns) {
            assertThat(v.get("hasPublicExploit")).isEqualTo(true);
            assertThat(v.get("detectedVersion")).isEqualTo("2.4.49");
            assertThat(v.get("remediation").toString()).contains("Upgrade Apache HTTP Server to version");
        }

        // Verify observations
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(3);
        assertThat(observations).allMatch(o -> o.severityHeuristic() == SeverityHeuristic.HIGH);
        assertThat(observations).allMatch(o -> "CVE_MATCH".equals(o.category()));
    }

    @Test
    @DisplayName("Matches jQuery 3.4.1 and Spring Boot 2.6.1 against CVE catalog")
    void matchesJqueryAndSpringBootVulnerabilities() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("tech_detect")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        List<Map<String, Object>> technologies = List.of(
                Map.of("name", "jQuery", "version", "3.4.1", "category", "Frontend Library", "confidence", "CONFIRMED"),
                Map.of("name", "Spring Boot", "version", "2.6.1", "category", "Backend Framework", "confidence", "CONFIRMED")
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("jQuery and Spring Boot detected")
                .parsedData(Map.of("technologies", technologies))
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
        List<Map<String, Object>> vulns = (List<Map<String, Object>>) outcome.parsedData().get("vulnerabilities");
        assertThat(vulns).hasSize(2);

        List<String> cveIds = vulns.stream().map(v -> (String) v.get("cveId")).toList();
        assertThat(cveIds).containsExactlyInAnyOrder("CVE-2020-11022", "CVE-2022-22965");

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(2);
        assertThat(observations).anyMatch(o -> o.description().contains("CVE-2020-11022") && o.severityHeuristic() == SeverityHeuristic.MEDIUM);
        assertThat(observations).anyMatch(o -> o.description().contains("CVE-2022-22965") && o.severityHeuristic() == SeverityHeuristic.HIGH);
    }

    @Test
    @DisplayName("Patched versions (Apache 2.4.58, Nginx 1.24.0, jQuery 3.7.1) produce zero CVE matches")
    void patchedVersionsProduceZeroMatches() throws Exception {
        UUID stepId = UUID.randomUUID();
        ToolExecution execution = ToolExecution.builder()
                .session(currentSession)
                .toolId("tech_detect")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();

        List<Map<String, Object>> technologies = List.of(
                Map.of("name", "Apache HTTP Server", "version", "2.4.58", "category", "Web Server", "confidence", "CONFIRMED"),
                Map.of("name", "Nginx", "version", "1.24.0", "category", "Web Server", "confidence", "CONFIRMED"),
                Map.of("name", "jQuery", "version", "3.7.1", "category", "Frontend Library", "confidence", "CONFIRMED")
        );

        ToolResult result = ToolResult.builder()
                .execution(execution)
                .rawOutput("Patched versions detected")
                .parsedData(Map.of("technologies", technologies))
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

        assertThat(outcome.parsedData().get("matchedCount")).isEqualTo(0);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> vulns = (List<Map<String, Object>>) outcome.parsedData().get("vulnerabilities");
        assertThat(vulns).isEmpty();
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("BOLA Guard: Referencing a step belonging to another session throws ResourceNotFoundException (preventing IDOR)")
    void bolaGuardRejectsCrossSessionStepReference() {
        UUID stepId = UUID.randomUUID();
        ToolExecution foreignExecution = ToolExecution.builder()
                .session(otherSession) // Belongs to otherSession!
                .toolId("tech_detect")
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
    @DisplayName("Prerequisite guard: Referencing a non-completed or non-tech_detect step throws ValidationException")
    void prerequisiteGuardRejectsIncompleteOrWrongToolStep() {
        UUID wrongToolStepId = UUID.randomUUID();
        ToolExecution wrongToolExecution = ToolExecution.builder()
                .session(currentSession)
                .toolId("http_headers") // Wrong tool!
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .createdAt(Instant.now())
                .build();
        when(toolExecutionRepository.findById(wrongToolStepId)).thenReturn(Optional.of(wrongToolExecution));

        ToolExecutionContext context = new ToolExecutionContext(
                currentSessionId,
                UUID.randomUUID(),
                "https://example.com",
                SessionMode.PUBLIC,
                null,
                Map.of("stepId", wrongToolStepId.toString()),
                null
        );

        assertThatThrownBy(() -> tool.execute(context))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("stepId");
                    assertThat(ve.getInvalidParams().get(0).reason()).contains("completed tech_detect execution");
                });
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

    @Test
    @DisplayName("Semantic version comparator handles various formats and prefixes")
    void semanticVersionComparator() {
        assertThat(CveMatcherTool.compareVersions("2.4.49", "2.4.49")).isEqualTo(0);
        assertThat(CveMatcherTool.compareVersions("v2.4.49", "2.4.49")).isEqualTo(0);
        assertThat(CveMatcherTool.compareVersions("2.4.49", "2.4.50")).isLessThan(0);
        assertThat(CveMatcherTool.compareVersions("2.4.51", "2.4.50")).isGreaterThan(0);
        assertThat(CveMatcherTool.compareVersions("2.4.0", "2.4")).isEqualTo(0);
        assertThat(CveMatcherTool.compareVersions("8.1.2", "8.0.0")).isGreaterThan(0);
        assertThat(CveMatcherTool.compareVersions("8.1.2", "8.3.7")).isLessThan(0);
    }
}
