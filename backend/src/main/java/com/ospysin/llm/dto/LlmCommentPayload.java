package com.ospysin.llm.dto;

import java.time.Instant;
import java.util.UUID;

public record LlmCommentPayload(
        UUID stepId,
        String toolId,
        String comment,
        String suggestedTool,
        String suggestedReason,
        Instant timestamp
) {}
