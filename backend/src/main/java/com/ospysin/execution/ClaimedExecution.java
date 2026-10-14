package com.ospysin.execution;

import com.ospysin.sessions.SessionMode;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Detached snapshot of a claimed tool execution passed to Phase 2 worker execution.
 */
public record ClaimedExecution(
        UUID executionId,
        UUID sessionId,
        UUID engagementId,
        String toolId,
        int claimedEpoch,
        Map<String, Object> inputParams,
        String targetUrl,
        SessionMode sessionMode,
        Instant startedAt
) {
    public ClaimedExecution {
        Objects.requireNonNull(executionId, "executionId must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(toolId, "toolId must not be null");
        Objects.requireNonNull(targetUrl, "targetUrl must not be null");
        Objects.requireNonNull(sessionMode, "sessionMode must not be null");
        Objects.requireNonNull(startedAt, "startedAt must not be null");
        inputParams = inputParams != null ? Collections.unmodifiableMap(inputParams) : Collections.emptyMap();
    }
}
