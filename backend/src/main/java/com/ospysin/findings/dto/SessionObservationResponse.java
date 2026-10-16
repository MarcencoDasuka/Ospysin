package com.ospysin.findings.dto;

import com.ospysin.observations.SeverityHeuristic;

import java.time.Instant;
import java.util.UUID;

public record SessionObservationResponse(
        UUID id,
        UUID executionId,
        UUID resultId,
        String toolId,
        String category,
        String description,
        SeverityHeuristic severityHeuristic,
        Instant detectedAt
) {
}
