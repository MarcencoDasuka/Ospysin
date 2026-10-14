package com.ospysin.tools;

import com.ospysin.observations.SeverityHeuristic;

import java.util.Objects;

/**
 * Draft observation extracted from tool execution before persistence.
 */
public record ObservationDraft(
        String category,
        String description,
        SeverityHeuristic severityHeuristic
) {
    public ObservationDraft {
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(description, "description must not be null");
        Objects.requireNonNull(severityHeuristic, "severityHeuristic must not be null");
    }
}
