package com.ospysin.tools;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable metadata and JSON input schema contract for a tool registered in the catalog.
 */
public record ToolMetadata(
        String id,
        String name,
        String category,
        ExecutionType executionType,
        String description,
        Map<String, Object> inputSchema
) {
    public ToolMetadata {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(category, "category must not be null");
        Objects.requireNonNull(executionType, "executionType must not be null");
        Objects.requireNonNull(description, "description must not be null");
        inputSchema = inputSchema != null ? Collections.unmodifiableMap(inputSchema) : Collections.emptyMap();
    }
}
