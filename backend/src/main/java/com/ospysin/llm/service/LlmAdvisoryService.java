package com.ospysin.llm.service;

import com.ospysin.llm.budget.LlmContextBudgeter;
import com.ospysin.llm.client.LlmClient;
import com.ospysin.llm.dto.*;
import com.ospysin.llm.parser.LlmCommentParsedResult;
import com.ospysin.llm.parser.LlmResponseParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.UUID;

/**
 * Asynchronous orchestration service for LLM Comment and Chat advisory.
 * Executes external HTTP calls to Ollama strictly detached from database transactions.
 */
@Slf4j
@Service
public class LlmAdvisoryService {

    private final LlmAdvisoryTxService llmAdvisoryTxService;
    private final LlmContextBudgeter llmContextBudgeter;
    private final LlmResponseParser llmResponseParser;
    private final LlmClient llmClient;
    private final ThreadPoolTaskExecutor llmAdvisoryExecutor;
    private final Clock clock;

    public LlmAdvisoryService(
            LlmAdvisoryTxService llmAdvisoryTxService,
            LlmContextBudgeter llmContextBudgeter,
            LlmResponseParser llmResponseParser,
            LlmClient llmClient,
            @Qualifier("llmAdvisoryExecutor") ThreadPoolTaskExecutor llmAdvisoryExecutor,
            Clock clock
    ) {
        this.llmAdvisoryTxService = llmAdvisoryTxService;
        this.llmContextBudgeter = llmContextBudgeter;
        this.llmResponseParser = llmResponseParser;
        this.llmClient = llmClient;
        this.llmAdvisoryExecutor = llmAdvisoryExecutor;
        this.clock = clock;
    }

    /**
     * Submits step commentary task asynchronously to dedicated bounded thread pool.
     */
    public void submitStepCommentAsync(UUID sessionId, UUID stepId) {
        log.debug("Submitting step commentary task for session {} step {}", sessionId, stepId);
        llmAdvisoryExecutor.execute(() -> executeStepComment(sessionId, stepId));
    }

    /**
     * Executes 3-step detached commentary workflow outside of database transaction:
     * 1. Read context & record LLM_QUERY (in short Tx)
     * 2. Assemble bounded prompt & execute remote HTTP call (NO Tx)
     * 3. Record LLM_COMMENT & broadcast SSE (in short Tx)
     */
    public void executeStepComment(UUID sessionId, UUID stepId) {
        log.info("Executing LLM step commentary for session {} and step {}", sessionId, stepId);
        CommentContextSnapshot context;
        try {
            context = llmAdvisoryTxService.loadStepContextAndRecordQuery(sessionId, stepId);
        } catch (Exception ex) {
            log.error("Failed to load step context for LLM commentary (session={}, step={}): {}",
                    sessionId, stepId, ex.getMessage(), ex);
            return;
        }

        PromptPair prompts = llmContextBudgeter.buildCommentPrompts(context.sessionSnapshot(), context.stepSnapshot());

        LlmCommentPayload payload;
        try {
            String rawJson = llmClient.generateCommentJson(prompts.system(), prompts.user());
            LlmCommentParsedResult parsed = llmResponseParser.parseComment(rawJson, context.stepSnapshot().toolId());
            payload = new LlmCommentPayload(
                    stepId,
                    context.stepSnapshot().toolId(),
                    parsed.comment(),
                    parsed.suggestedTool(),
                    parsed.suggestedReason(),
                    clock.instant()
            );
        } catch (Exception ex) {
            log.warn("LLM advisory unavailable or failed for step {} (session {}): {}", stepId, sessionId, ex.getMessage());
            payload = new LlmCommentPayload(
                    stepId,
                    context.stepSnapshot().toolId(),
                    "LLM advisor unavailable - verify Ollama is running",
                    null,
                    null,
                    clock.instant()
            );
        }

        try {
            llmAdvisoryTxService.recordCommentAndBroadcast(sessionId, payload);
        } catch (Exception ex) {
            log.error("Failed to record LLM comment and broadcast SSE for session {}: {}", sessionId, ex.getMessage(), ex);
        }
    }

    /**
     * Submits free chat query task asynchronously to dedicated bounded thread pool.
     */
    public void submitChatAsync(UUID sessionId, String message) {
        log.debug("Submitting chat query task for session {}", sessionId);
        llmAdvisoryExecutor.execute(() -> executeChat(sessionId, message));
    }

    /**
     * Executes 3-step detached chat workflow outside of database transaction:
     * 1. Read context & record LLM_QUERY (in short Tx)
     * 2. Assemble bounded prompt & execute remote HTTP call (NO Tx)
     * 3. Record LLM_COMMENT & broadcast SSE (in short Tx)
     */
    public void executeChat(UUID sessionId, String message) {
        log.info("Executing LLM chat query for session {}", sessionId);
        SessionContextSnapshot context;
        try {
            context = llmAdvisoryTxService.loadChatContextAndRecordQuery(sessionId, message);
        } catch (Exception ex) {
            log.error("Failed to load chat context for session {}: {}", sessionId, ex.getMessage(), ex);
            return;
        }

        PromptPair prompts = llmContextBudgeter.buildChatPrompts(context, message);

        LlmChatReplyPayload payload;
        try {
            String reply = llmClient.generateChatReply(prompts.system(), prompts.user());
            payload = new LlmChatReplyPayload(reply, clock.instant());
        } catch (Exception ex) {
            log.warn("LLM chat query failed for session {}: {}", sessionId, ex.getMessage());
            payload = new LlmChatReplyPayload("LLM advisor unavailable - verify Ollama is running", clock.instant());
        }

        try {
            llmAdvisoryTxService.recordChatReplyAndBroadcast(sessionId, payload);
        } catch (Exception ex) {
            log.error("Failed to record LLM chat reply and broadcast SSE for session {}: {}", sessionId, ex.getMessage(), ex);
        }
    }
}
