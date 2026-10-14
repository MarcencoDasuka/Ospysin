package com.ospysin.observations;

import com.ospysin.execution.ToolResult;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "observations")
@org.hibernate.annotations.Immutable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Observation {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "result_id", nullable = false)
    private ToolResult result;

    @Column(name = "category", nullable = false, length = 50)
    private String category;

    @Column(name = "description", nullable = false, columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity_heuristic", nullable = false, length = 20)
    private SeverityHeuristic severityHeuristic;

    @Column(name = "detected_at", nullable = false, updatable = false)
    private Instant detectedAt;

    @Builder
    private Observation(ToolResult result, String category, String description,
                        SeverityHeuristic severityHeuristic, Instant detectedAt) {
        this.result = result;
        this.category = category;
        this.description = description;
        this.severityHeuristic = severityHeuristic;
        this.detectedAt = detectedAt != null ? detectedAt : Instant.now();
    }
}
