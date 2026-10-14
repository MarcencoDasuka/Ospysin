package com.ospysin;

import com.ospysin.engagements.Engagement;
import com.ospysin.engagements.EngagementRepository;
import com.ospysin.engagements.EngagementStatus;
import com.ospysin.evidence.Evidence;
import com.ospysin.evidence.EvidenceRepository;
import com.ospysin.execution.*;
import com.ospysin.findings.*;
import com.ospysin.identity.User;
import com.ospysin.identity.UserRepository;
import com.ospysin.identity.UserRole;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FlywaySchemaAndEntitiesIT extends AbstractIntegrationTest {

    private static final UUID DEFAULT_PROJECT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

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

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Verifies Flyway schema validation and pre-seeded Default Project existence")
    void shouldVerifyFlywaySchemaAndDefaultProject() {
        Optional<Project> defaultProject = projectRepository.findById(DEFAULT_PROJECT_ID);
        assertThat(defaultProject).isPresent();
        assertThat(defaultProject.get().getName()).isEqualTo("Default Project");
    }

    @Test
    @DisplayName("Verifies AdminUserInitializer provisions default admin operator")
    void shouldVerifyAdminUserBootstrapped() {
        Optional<User> admin = userRepository.findByUsername("admin");
        assertThat(admin).isPresent();
        assertThat(admin.get().getRole()).isEqualTo(UserRole.ADMIN);
        assertThat(admin.get().getPasswordHash()).isNotEmpty();
    }

    @Test
    @DisplayName("Persists and retrieves full domain entity chain with JSONB and timestamps")
    void shouldPersistAndRetrieveFullEntityChain() {
        // 1. Project
        Project project = projectRepository.save(Project.builder()
                .name("Internal Finance Portal")
                .description("Q4 Security Assessment for Internal Banking")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build());
        assertThat(project.getId()).isNotNull();

        // 2. Engagement
        Engagement engagement = engagementRepository.save(Engagement.builder()
                .project(project)
                .title("Stage 1 External Recon")
                .startDate(LocalDate.of(2026, 10, 15))
                .endDate(LocalDate.of(2026, 10, 30))
                .status(EngagementStatus.ACTIVE)
                .createdAt(Instant.now())
                .build());
        assertThat(engagement.getId()).isNotNull();

        // 3. ScopeAsset
        ScopeAsset scopeAsset = scopeAssetRepository.save(ScopeAsset.builder()
                .engagement(engagement)
                .assetType(AssetType.FQDN)
                .value("portal.finance.internal")
                .isWildcard(false)
                .createdAt(Instant.now())
                .build());
        assertThat(scopeAsset.getId()).isNotNull();

        // 4. AuditSession
        AuditSession session = auditSessionRepository.save(AuditSession.builder()
                .engagement(engagement)
                .targetUrl("https://portal.finance.internal")
                .mode(SessionMode.LOCAL)
                .state(SessionState.ACTIVE)
                .scopeAcknowledged(true)
                .scopeAckVersion("1.0.0")
                .scopeAckText("Authorized by Security Lead")
                .scopeAckHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .scopeAckTimestamp(Instant.now())
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build());
        assertThat(session.getId()).isNotNull();

        // 5. ToolExecution with JSONB input_params
        ToolExecution execution = toolExecutionRepository.save(ToolExecution.builder()
                .session(session)
                .toolId("http_headers")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of("customPort", 8443, "followRedirects", false))
                .durationMs(450L)
                .createdAt(Instant.now())
                .startedAt(Instant.now())
                .endedAt(Instant.now())
                .build());
        assertThat(execution.getId()).isNotNull();
        assertThat(execution.getInputParams()).containsEntry("customPort", 8443);

        // 6. ToolResult (Immutable) with JSONB parsed_data
        ToolResult result = toolResultRepository.save(ToolResult.builder()
                .execution(execution)
                .rawOutput("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nX-Frame-Options: SAMEORIGIN")
                .parsedData(Map.of("server", "Apache/2.4.41", "hasHsts", false))
                .score(85)
                .hasErrors(false)
                .createdAt(Instant.now())
                .build());
        assertThat(result.getId()).isNotNull();
        assertThat(result.getParsedData()).containsEntry("hasHsts", false);

        // 7. Observation
        Observation observation = observationRepository.save(Observation.builder()
                .result(result)
                .category("HTTP_SECURITY")
                .description("Server response leaks detailed version banner in Server header")
                .severityHeuristic(SeverityHeuristic.LOW)
                .detectedAt(Instant.now())
                .build());
        assertThat(observation.getId()).isNotNull();

        // 8. Finding
        Finding finding = findingRepository.save(Finding.builder()
                .session(session)
                .observation(observation)
                .title("Information Disclosure via Server Header")
                .description("Web server announces Apache version 2.4.41")
                .severity(FindingSeverity.LOW)
                .confidence(FindingConfidence.CONFIRMED)
                .status(FindingStatus.CONFIRMED)
                .remediation("Configure ServerTokens Prod in Apache httpd configuration")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build());
        assertThat(finding.getId()).isNotNull();

        // 9. Evidence
        Evidence evidence = evidenceRepository.save(Evidence.builder()
                .finding(finding)
                .result(result)
                .snippet("Server: Apache/2.4.41")
                .createdAt(Instant.now())
                .build());
        assertThat(evidence.getId()).isNotNull();

        // 10. AuditEvent (Append-only) with JSONB payload
        AuditEvent auditEvent = auditEventRepository.save(AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.FINDING_CREATED)
                .payload(Map.of("findingId", finding.getId().toString(), "operator", "admin"))
                .timestamp(Instant.now())
                .build());
        assertThat(auditEvent.getId()).isNotNull();
        assertThat(auditEvent.getPayload()).containsEntry("operator", "admin");

        // Verify retrieval across relations
        Optional<Finding> reloadedFinding = findingRepository.findById(finding.getId());
        assertThat(reloadedFinding).isPresent();
        assertThat(reloadedFinding.get().getSession().getId()).isEqualTo(session.getId());
        assertThat(reloadedFinding.get().getObservation().getId()).isEqualTo(observation.getId());

        Optional<ToolResult> reloadedResult = toolResultRepository.findByExecutionId(execution.getId());
        assertThat(reloadedResult).isPresent();
        assertThat(reloadedResult.get().getParsedData().get("server")).isEqualTo("Apache/2.4.41");
    }
}
