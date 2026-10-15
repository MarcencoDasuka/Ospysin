package com.ospysin.llm.dto;

import java.time.Instant;

public record LlmChatReplyPayload(
        String reply,
        Instant timestamp
) {}
