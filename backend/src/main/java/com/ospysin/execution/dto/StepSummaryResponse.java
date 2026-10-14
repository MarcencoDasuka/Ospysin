package com.ospysin.execution.dto;

import com.ospysin.execution.ExecutionStatus;

import java.time.Instant;
import java.util.UUID;

/**
 * Summary DTO for steps listed in GET /api/sessions/{id}/steps.
 */
public record StepSummaryResponse(
        UUID executionId,
        String toolId,
        ExecutionStatus status,
        Long durationMs,
        long observationCount,
        Instant startedAt,
        Instant endedAt
) {}
