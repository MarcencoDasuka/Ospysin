package com.ospysin.llm.dto;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record StepContextSnapshot(
        UUID stepId,
        String toolId,
        Map<String, Object> inputParams,
        Map<String, Object> parsedData,
        String rawOutput,
        List<String> observations
) {
    public StepContextSnapshot {
        inputParams = inputParams != null ? Collections.unmodifiableMap(inputParams) : Collections.emptyMap();
        parsedData = parsedData != null ? Collections.unmodifiableMap(parsedData) : Collections.emptyMap();
        observations = observations != null ? List.copyOf(observations) : List.of();
    }
}
