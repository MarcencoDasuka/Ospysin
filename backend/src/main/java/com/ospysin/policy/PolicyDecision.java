package com.ospysin.policy;

import com.ospysin.sessions.SessionMode;

import java.net.InetAddress;

public record PolicyDecision(
        boolean allowed,
        String reason,
        String targetHost,
        InetAddress resolvedIp,
        SessionMode mode,
        long evaluationTimestamp
) {
}
