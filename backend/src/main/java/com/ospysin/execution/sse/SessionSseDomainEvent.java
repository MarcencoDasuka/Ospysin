package com.ospysin.execution.sse;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Domain event dispatched for Server-Sent Events (SSE) broadcast.
 */
public record SessionSseDomainEvent(
        UUID sessionId,
        String eventName,
        Map<String, Object> data
) {
    public SessionSseDomainEvent {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(eventName, "eventName must not be null");
        data = data != null ? Collections.unmodifiableMap(data) : Collections.emptyMap();
    }
}
