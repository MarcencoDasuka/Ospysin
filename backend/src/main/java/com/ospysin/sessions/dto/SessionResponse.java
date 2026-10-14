package com.ospysin.sessions.dto;

import com.ospysin.sessions.SessionMode;
import com.ospysin.sessions.SessionState;

import java.time.Instant;
import java.util.UUID;

public record SessionResponse(
        UUID id,
        String targetUrl,
        SessionMode mode,
        SessionState state,
        boolean scopeAcknowledged,
        String scopeAckVersion,
        String scopeAckHash,
        Instant scopeAckTimestamp,
        long stepCount,
        long findingCount,
        Instant createdAt,
        Instant updatedAt
) {
}
