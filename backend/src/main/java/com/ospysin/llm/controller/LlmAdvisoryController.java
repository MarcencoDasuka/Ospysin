package com.ospysin.llm.controller;

import com.ospysin.llm.dto.LlmAsyncAcceptedResponse;
import com.ospysin.llm.dto.LlmChatRequest;
import com.ospysin.llm.dto.LlmCommentRequest;
import com.ospysin.llm.service.LlmAdvisoryService;
import com.ospysin.llm.service.LlmAdvisoryTxService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for Local LLM Advisory endpoints:
 * - On-demand step re-analysis (Comment Mode)
 * - Interactive tactical sounding board (Free Chat Mode)
 */
@Slf4j
@RestController
@RequestMapping("/api/sessions/{id}/llm")
@RequiredArgsConstructor
public class LlmAdvisoryController {

    private final LlmAdvisoryTxService llmAdvisoryTxService;
    private final LlmAdvisoryService llmAdvisoryService;

    /**
     * Enqueues an on-demand commentary re-generation task for a completed step.
     */
    @PostMapping("/comment")
    public ResponseEntity<LlmAsyncAcceptedResponse> requestStepComment(
            @PathVariable("id") UUID sessionId,
            @Valid @RequestBody LlmCommentRequest request
    ) {
        log.info("Received commentary request for session {} step {}", sessionId, request.stepId());
        // Synchronous validation: 404 on missing session, missing step, or BOLA mismatch
        llmAdvisoryTxService.validateStepAccess(sessionId, request.stepId());

        // Asynchronous background inference
        llmAdvisoryService.submitStepCommentAsync(sessionId, request.stepId());

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(new LlmAsyncAcceptedResponse("PENDING", "LLM commentary request enqueued"));
    }

    /**
     * Enqueues an interactive tactical chat query grounded in session audit context.
     */
    @PostMapping("/chat")
    public ResponseEntity<LlmAsyncAcceptedResponse> sendChatMessage(
            @PathVariable("id") UUID sessionId,
            @Valid @RequestBody LlmChatRequest request
    ) {
        log.info("Received chat query for session {}", sessionId);
        // Synchronous validation: 404 if not found, 409 if session not ACTIVE
        llmAdvisoryTxService.validateChatAccess(sessionId);

        // Asynchronous background inference
        llmAdvisoryService.submitChatAsync(sessionId, request.message());

        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(new LlmAsyncAcceptedResponse("PENDING", "Chat query enqueued"));
    }
}
