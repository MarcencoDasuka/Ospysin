package com.ospysin.llm.dto;

import com.ospysin.sessions.SessionMode;

import java.util.List;
import java.util.UUID;

public record SessionContextSnapshot(
        UUID sessionId,
        String targetUrl,
        SessionMode mode,
        List<CompletedStepSummary> completedSteps
) {
    public SessionContextSnapshot {
        completedSteps = completedSteps != null ? List.copyOf(completedSteps) : List.of();
    }
}
