package com.ospysin.execution;

import com.ospysin.execution.dto.StepDetailResponse;
import com.ospysin.execution.dto.StepSummaryResponse;
import com.ospysin.execution.dto.ToolRunAcceptedResponse;
import com.ospysin.tools.ToolCatalogRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Controller exposing tool execution triggering, step history, and step detail endpoints.
 */
@RestController
@RequestMapping("/api/sessions/{id}")
@RequiredArgsConstructor
public class ToolExecutionController {

    private final ToolExecutionTxService toolExecutionTxService;
    private final ToolCatalogRegistry toolCatalogRegistry;

    @PostMapping("/tools/{toolId}/run")
    @SuppressWarnings("unchecked")
    public ResponseEntity<ToolRunAcceptedResponse> runTool(
            @PathVariable("id") UUID sessionId,
            @PathVariable("toolId") String toolId,
            @RequestBody(required = false) Map<String, Object> body
    ) {
        // 1. Tool Catalog validation (400 if unknown tool)
        if (!toolCatalogRegistry.isRegistered(toolId)) {
            throw new IllegalArgumentException("Unknown tool ID: " + toolId);
        }

        // Extract params: handle both direct map and wrapped { "params": { ... } }
        Map<String, Object> params = Collections.emptyMap();
        if (body != null) {
            if (body.containsKey("params") && body.get("params") instanceof Map<?, ?> nested) {
                params = (Map<String, Object>) nested;
            } else {
                params = body;
            }
        }

        // 2. Validate input parameters against tool schema (422 if invalid)
        toolCatalogRegistry.validateParams(toolId, params);

        // 3. Enqueue execution (404 if session not found, 409 if session not active or duplicate active job)
        ToolExecution execution = toolExecutionTxService.enqueueExecution(sessionId, toolId, params);

        URI location = URI.create("/api/sessions/" + sessionId + "/steps/" + execution.getId());
        ToolRunAcceptedResponse response = new ToolRunAcceptedResponse(
                execution.getId(),
                sessionId.toString(),
                toolId,
                execution.getStatus(),
                execution.getCreatedAt()
        );

        return ResponseEntity.accepted()
                .header(HttpHeaders.LOCATION, location.toString())
                .body(response);
    }

    @GetMapping("/steps")
    public ResponseEntity<List<StepSummaryResponse>> getSteps(@PathVariable("id") UUID sessionId) {
        return ResponseEntity.ok(toolExecutionTxService.getSteps(sessionId));
    }

    @GetMapping("/steps/{stepId}")
    public ResponseEntity<StepDetailResponse> getStepDetail(
            @PathVariable("id") UUID sessionId,
            @PathVariable("stepId") UUID stepId
    ) {
        return ResponseEntity.ok(toolExecutionTxService.getStepDetail(sessionId, stepId));
    }
}
