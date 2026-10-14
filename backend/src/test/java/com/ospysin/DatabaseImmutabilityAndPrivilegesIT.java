package com.ospysin;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.sql.DataSource;
import java.sql.*;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DatabaseImmutabilityAndPrivilegesIT extends AbstractIntegrationTest {

    @Autowired
    private DataSource dataSource;

    @Test
    @DisplayName("PostgreSQL triggers strictly prohibit UPDATE, DELETE, and TRUNCATE on tool_results")
    void shouldBlockMutationsOnToolResultsViaTrigger() throws SQLException {
        UUID executionId = UUID.randomUUID();
        UUID resultId = UUID.randomUUID();

        try (Connection conn = dataSource.getConnection()) {
            // Seed session, execution and tool_result
            seedExecutionAndResult(conn, executionId, resultId);

            // 1. UPDATE must fail
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE tool_results SET score = 99 WHERE id = ?")) {
                stmt.setObject(1, resultId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("strictly append-only");
            }

            // 2. DELETE must fail
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM tool_results WHERE id = ?")) {
                stmt.setObject(1, resultId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("strictly append-only");
            }

            // 3. TRUNCATE must fail
            try (Statement stmt = conn.createStatement()) {
                assertThatThrownBy(() -> stmt.execute("TRUNCATE TABLE tool_results CASCADE"))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("strictly append-only");
            }
        }
    }

    @Test
    @DisplayName("PostgreSQL triggers strictly prohibit UPDATE, DELETE, and TRUNCATE on audit_events")
    void shouldBlockMutationsOnAuditEventsViaTrigger() throws SQLException {
        UUID eventId = UUID.randomUUID();

        try (Connection conn = dataSource.getConnection()) {
            // Seed audit event
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO audit_events (id, event_type, payload, timestamp) VALUES (?, 'SESSION_STARTED', '{}'::jsonb, NOW())")) {
                stmt.setObject(1, eventId);
                stmt.executeUpdate();
            }

            // 1. UPDATE must fail
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE audit_events SET event_type = 'SESSION_COMPLETED' WHERE id = ?")) {
                stmt.setObject(1, eventId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("strictly append-only");
            }

            // 2. DELETE must fail
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM audit_events WHERE id = ?")) {
                stmt.setObject(1, eventId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("strictly append-only");
            }

            // 3. TRUNCATE must fail
            try (Statement stmt = conn.createStatement()) {
                assertThatThrownBy(() -> stmt.execute("TRUNCATE TABLE audit_events"))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("strictly append-only");
            }
        }
    }

    @Test
    @DisplayName("Foreign key ON DELETE RESTRICT blocks deletion of parent project, engagement, and session")
    void shouldEnforceOnDeleteRestrictAcrossHierarchy() throws SQLException {
        UUID projectId = UUID.randomUUID();
        UUID engagementId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID executionId = UUID.randomUUID();
        UUID resultId = UUID.randomUUID();

        try (Connection conn = dataSource.getConnection()) {
            // 1. Insert Project
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'Restrict Test', NOW(), NOW())")) {
                stmt.setObject(1, projectId);
                stmt.executeUpdate();
            }

            // 2. Insert Engagement
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO engagements (id, project_id, title, start_date, status, created_at) VALUES (?, ?, 'Eng 1', CURRENT_DATE, 'ACTIVE', NOW())")) {
                stmt.setObject(1, engagementId);
                stmt.setObject(2, projectId);
                stmt.executeUpdate();
            }

            // 3. Insert AuditSession
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO audit_sessions (id, engagement_id, target_url, mode, state, created_at, updated_at) VALUES (?, ?, 'https://test.local', 'LOCAL', 'ACTIVE', NOW(), NOW())")) {
                stmt.setObject(1, sessionId);
                stmt.setObject(2, engagementId);
                stmt.executeUpdate();
            }

            // 4. Insert ToolExecution & ToolResult
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO tool_executions (id, session_id, tool_id, status, created_at) VALUES (?, ?, 'test_tool', 'COMPLETED', NOW())")) {
                stmt.setObject(1, executionId);
                stmt.setObject(2, sessionId);
                stmt.executeUpdate();
            }
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO tool_results (id, execution_id, raw_output, parsed_data, created_at) VALUES (?, ?, 'test output', '{}'::jsonb, NOW())")) {
                stmt.setObject(1, resultId);
                stmt.setObject(2, executionId);
                stmt.executeUpdate();
            }

            // Deleting session must fail due to child tool_executions (RESTRICT)
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM audit_sessions WHERE id = ?")) {
                stmt.setObject(1, sessionId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class);
            }

            // Deleting engagement must fail due to child audit_sessions (RESTRICT)
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM engagements WHERE id = ?")) {
                stmt.setObject(1, engagementId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class);
            }

            // Deleting project must fail due to child engagements (RESTRICT)
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM projects WHERE id = ?")) {
                stmt.setObject(1, projectId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class);
            }
        }
    }

    @Test
    @DisplayName("Runtime database role ospysin_app cannot mutate or truncate append-only tables")
    void shouldEnforcePrivilegeSeparationForAppRole() throws SQLException {
        // Connect directly as unprivileged runtime user ospysin_app (privileges provisioned by V1 migration)
        try (Connection appConn = DriverManager.getConnection(
                postgres.getJdbcUrl(), "ospysin_app", "app_secret_test")) {

            UUID executionId = UUID.randomUUID();
            UUID resultId = UUID.randomUUID();

            // Setup prerequisites as admin first
            try (Connection adminConn = dataSource.getConnection()) {
                seedExecutionAndResult(adminConn, executionId, resultId);
            }

            // ospysin_app CAN SELECT
            try (PreparedStatement stmt = appConn.prepareStatement("SELECT COUNT(*) FROM tool_results WHERE id = ?")) {
                stmt.setObject(1, resultId);
                try (ResultSet rs = stmt.executeQuery()) {
                    assertThat(rs.next()).isTrue();
                    assertThat(rs.getInt(1)).isEqualTo(1);
                }
            }

            // ospysin_app CANNOT UPDATE (REVOKED privilege / permission denied)
            try (PreparedStatement stmt = appConn.prepareStatement("UPDATE tool_results SET score = 50 WHERE id = ?")) {
                stmt.setObject(1, resultId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("permission denied");
            }

            // ospysin_app CANNOT DELETE (permission denied)
            try (PreparedStatement stmt = appConn.prepareStatement("DELETE FROM tool_results WHERE id = ?")) {
                stmt.setObject(1, resultId);
                assertThatThrownBy(stmt::executeUpdate)
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("permission denied");
            }

            // ospysin_app CANNOT TRUNCATE (permission denied)
            try (Statement stmt = appConn.createStatement()) {
                assertThatThrownBy(() -> stmt.execute("TRUNCATE TABLE tool_results"))
                        .isInstanceOf(SQLException.class)
                        .hasMessageContaining("permission denied");
            }
        }
    }

    private void seedExecutionAndResult(Connection conn, UUID executionId, UUID resultId) throws SQLException {
        UUID projectId = UUID.randomUUID();
        UUID engagementId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();

        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, 'Seed Proj', NOW(), NOW())")) {
            stmt.setObject(1, projectId);
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO engagements (id, project_id, title, start_date, status, created_at) VALUES (?, ?, 'Seed Eng', CURRENT_DATE, 'ACTIVE', NOW())")) {
            stmt.setObject(1, engagementId);
            stmt.setObject(2, projectId);
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO audit_sessions (id, engagement_id, target_url, mode, state, created_at, updated_at) VALUES (?, ?, 'https://seed.test', 'LOCAL', 'ACTIVE', NOW(), NOW())")) {
            stmt.setObject(1, sessionId);
            stmt.setObject(2, engagementId);
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO tool_executions (id, session_id, tool_id, status, created_at) VALUES (?, ?, 'test_tool', 'COMPLETED', NOW())")) {
            stmt.setObject(1, executionId);
            stmt.setObject(2, sessionId);
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO tool_results (id, execution_id, raw_output, parsed_data, created_at) VALUES (?, ?, 'seed output', '{}'::jsonb, NOW())")) {
            stmt.setObject(1, resultId);
            stmt.setObject(2, executionId);
            stmt.executeUpdate();
        }
    }
}
