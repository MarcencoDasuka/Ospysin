package com.ospysin.tools;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Output resulting from an OspysinTool execution.
 */
public record ToolExecutionOutcome(
        String rawOutput,
        Map<String, Object> parsedData,
        Integer score,
        boolean hasErrors,
        List<ObservationDraft> observations
) {
    public ToolExecutionOutcome {
        Objects.requireNonNull(rawOutput, "rawOutput must not be null");
        parsedData = parsedData != null ? Collections.unmodifiableMap(parsedData) : Collections.emptyMap();
        observations = observations != null ? List.copyOf(observations) : Collections.emptyList();
    }
}
