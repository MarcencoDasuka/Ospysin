package com.ospysin.execution.dto;

import com.ospysin.execution.ExecutionStatus;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Detailed step response for GET /api/sessions/{id}/steps/{stepId}.
 */
public record StepDetailResponse(
        UUID executionId,
        UUID resultId,
        String toolId,
        ExecutionStatus status,
        Long durationMs,
        String failureReason,
        String rawOutput,
        Map<String, Object> parsedData,
        Integer score,
        List<ObservationDto> observations,
        Instant startedAt,
        Instant endedAt
) {
    public StepDetailResponse {
        parsedData = parsedData != null ? Collections.unmodifiableMap(parsedData) : Collections.emptyMap();
        observations = observations != null ? List.copyOf(observations) : Collections.emptyList();
    }

    public StepDetailResponse(
            UUID executionId,
            String toolId,
            ExecutionStatus status,
            Long durationMs,
            String failureReason,
            String rawOutput,
            Map<String, Object> parsedData,
            Integer score,
            List<ObservationDto> observations,
            Instant startedAt,
            Instant endedAt
    ) {
        this(executionId, null, toolId, status, durationMs, failureReason, rawOutput, parsedData, score, observations, startedAt, endedAt);
    }
}
