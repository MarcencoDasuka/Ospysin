package com.ospysin.llm.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record LlmCommentRequest(
        @NotNull(message = "stepId is required")
        UUID stepId
) {}
