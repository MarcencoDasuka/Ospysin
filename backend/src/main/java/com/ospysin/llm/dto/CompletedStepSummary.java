package com.ospysin.llm.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record CompletedStepSummary(
        UUID stepId,
        String toolId,
        Instant finishedAt,
        List<String> observations
) {
    public CompletedStepSummary {
        observations = observations != null ? List.copyOf(observations) : List.of();
    }
}
