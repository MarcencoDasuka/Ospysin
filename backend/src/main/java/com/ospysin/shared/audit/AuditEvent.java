package com.ospysin.shared.audit;

import com.ospysin.sessions.AuditSession;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "audit_events")
@Immutable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id")
    private AuditSession session;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private AuditEventType eventType;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload", columnDefinition = "jsonb", nullable = false)
    private Map<String, Object> payload = new HashMap<>();

    @Column(name = "timestamp", nullable = false, updatable = false)
    private Instant timestamp;

    @Builder
    private AuditEvent(AuditSession session, AuditEventType eventType,
                       Map<String, Object> payload, Instant timestamp) {
        this.session = session;
        this.eventType = eventType;
        this.payload = payload != null ? new HashMap<>(payload) : new HashMap<>();
        this.timestamp = timestamp != null ? timestamp : Instant.now();
    }
}
