package com.ospysin.findings;

import com.ospysin.observations.Observation;
import com.ospysin.sessions.AuditSession;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "findings")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false)
    private AuditSession session;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "observation_id")
    private Observation observation;

    @Setter
    @Column(name = "title", nullable = false, length = 200)
    private String title;

    @Setter
    @Column(name = "description", nullable = false, columnDefinition = "TEXT")
    private String description;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 20)
    private FindingSeverity severity;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(name = "confidence", nullable = false, length = 20)
    private FindingConfidence confidence;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private FindingStatus status;

    @Setter
    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;

    @Setter
    @Column(name = "remediation", columnDefinition = "TEXT")
    private String remediation;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Setter
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Builder
    private Finding(AuditSession session, Observation observation, String title, String description,
                    FindingSeverity severity, FindingConfidence confidence, FindingStatus status,
                    String rejectionReason, String remediation, Instant createdAt, Instant updatedAt) {
        this.session = session;
        this.observation = observation;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.confidence = confidence != null ? confidence : FindingConfidence.TENTATIVE;
        this.status = status;
        this.rejectionReason = rejectionReason;
        this.remediation = remediation;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
        this.updatedAt = updatedAt != null ? updatedAt : Instant.now();
    }
}
