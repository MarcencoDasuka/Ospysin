package com.ospysin.execution;

import java.util.Objects;
import java.util.UUID;

/**
 * Internal application event published when a tool execution is successfully enqueued.
 */
public record ToolExecutionEnqueuedEvent(UUID executionId) {
    public ToolExecutionEnqueuedEvent {
        Objects.requireNonNull(executionId, "executionId must not be null");
    }
}
