package com.ospysin.execution.dto;

import com.ospysin.execution.ExecutionStatus;

import java.time.Instant;
import java.util.UUID;

/**
 * Response returned with 202 Accepted upon enqueuing a tool execution.
 */
public record ToolRunAcceptedResponse(
        UUID executionId,
        String sessionId,
        String toolId,
        ExecutionStatus status,
        Instant enqueuedAt
) {}
