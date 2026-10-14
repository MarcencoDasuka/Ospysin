package com.ospysin.tools;

import com.ospysin.policy.PolicyDecision;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Execution context passed to an OspysinTool SPI implementation.
 */
public record ToolExecutionContext(
        UUID sessionId,
        UUID executionId,
        String targetUrl,
        SessionMode mode,
        ScopeAsset scopeAsset,
        Map<String, Object> inputParams,
        PolicyDecision policyDecision
) {
    public ToolExecutionContext {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(executionId, "executionId must not be null");
        Objects.requireNonNull(targetUrl, "targetUrl must not be null");
        Objects.requireNonNull(mode, "mode must not be null");
        inputParams = inputParams != null ? Collections.unmodifiableMap(inputParams) : Collections.emptyMap();
    }
}
