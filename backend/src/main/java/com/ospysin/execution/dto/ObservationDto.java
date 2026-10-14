package com.ospysin.execution.dto;

import com.ospysin.observations.SeverityHeuristic;

import java.time.Instant;
import java.util.UUID;

/**
 * DTO representing an observation extracted from a tool execution result.
 */
public record ObservationDto(
        UUID id,
        String category,
        String description,
        SeverityHeuristic severityHeuristic,
        Instant detectedAt
) {}
