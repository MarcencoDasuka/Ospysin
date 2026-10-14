package com.ospysin.execution;

import com.ospysin.sessions.AuditSession;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "tool_executions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ToolExecution {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false)
    private AuditSession session;

    @Column(name = "tool_id", nullable = false, length = 50)
    private String toolId;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ExecutionStatus status;

    @Setter
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "input_params", columnDefinition = "jsonb", nullable = false)
    private Map<String, Object> inputParams = new HashMap<>();

    @Setter
    @Column(name = "lease_owner")
    private UUID leaseOwner;

    @Setter
    @Column(name = "lease_epoch", nullable = false)
    private int leaseEpoch;

    @Setter
    @Column(name = "lease_expires_at")
    private Instant leaseExpiresAt;

    @Setter
    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Setter
    @Column(name = "failure_reason", length = 100)
    private String failureReason;

    @Setter
    @Column(name = "duration_ms")
    private Long durationMs;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Setter
    @Column(name = "started_at")
    private Instant startedAt;

    @Setter
    @Column(name = "ended_at")
    private Instant endedAt;

    @Builder
    private ToolExecution(AuditSession session, String toolId, ExecutionStatus status,
                          Map<String, Object> inputParams, UUID leaseOwner, Integer leaseEpoch,
                          Instant leaseExpiresAt, Integer attempts, String failureReason,
                          Long durationMs, Instant createdAt, Instant startedAt, Instant endedAt) {
        this.session = session;
        this.toolId = toolId;
        this.status = status;
        this.inputParams = inputParams != null ? new HashMap<>(inputParams) : new HashMap<>();
        this.leaseOwner = leaseOwner;
        this.leaseEpoch = leaseEpoch != null ? leaseEpoch : 0;
        this.leaseExpiresAt = leaseExpiresAt;
        this.attempts = attempts != null ? attempts : 0;
        this.failureReason = failureReason;
        this.durationMs = durationMs;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
        this.startedAt = startedAt;
        this.endedAt = endedAt;
    }
}
