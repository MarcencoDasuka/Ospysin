package com.ospysin.llm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LlmChatRequest(
        @NotBlank(message = "message must not be blank")
        @Size(max = 2000, message = "message must not exceed 2000 characters")
        String message
) {}
