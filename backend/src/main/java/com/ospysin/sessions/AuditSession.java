package com.ospysin.sessions;

import com.ospysin.engagements.Engagement;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_sessions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "engagement_id", nullable = false)
    private Engagement engagement;

    @Column(name = "target_url", nullable = false, length = 500)
    private String targetUrl;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(name = "mode", nullable = false, length = 20)
    private SessionMode mode;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, length = 20)
    private SessionState state;

    @Setter
    @Column(name = "scope_acknowledged", nullable = false)
    private boolean scopeAcknowledged;

    @Setter
    @Column(name = "scope_ack_version", length = 20)
    private String scopeAckVersion;

    @Setter
    @Column(name = "scope_ack_text", columnDefinition = "TEXT")
    private String scopeAckText;

    @Setter
    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.CHAR)
    @Column(name = "scope_ack_hash", length = 64)
    private String scopeAckHash;

    @Setter
    @Column(name = "scope_ack_timestamp")
    private Instant scopeAckTimestamp;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Setter
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Builder
    private AuditSession(Engagement engagement, String targetUrl, SessionMode mode, SessionState state,
                         Boolean scopeAcknowledged, String scopeAckVersion, String scopeAckText,
                         String scopeAckHash, Instant scopeAckTimestamp, Instant createdAt, Instant updatedAt) {
        this.engagement = engagement;
        this.targetUrl = targetUrl;
        this.mode = mode;
        this.state = state;
        this.scopeAcknowledged = scopeAcknowledged != null ? scopeAcknowledged : false;
        this.scopeAckVersion = scopeAckVersion;
        this.scopeAckText = scopeAckText;
        this.scopeAckHash = scopeAckHash;
        this.scopeAckTimestamp = scopeAckTimestamp;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
        this.updatedAt = updatedAt != null ? updatedAt : Instant.now();
    }
}
