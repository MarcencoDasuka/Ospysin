package com.ospysin.sessions.dto;

import com.ospysin.sessions.SessionMode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record CreateSessionRequest(
        @NotBlank(message = "Target URL must not be blank")
        @Size(max = 500, message = "Target URL must not exceed 500 characters")
        String targetUrl,

        @NotNull(message = "Session mode must not be null")
        SessionMode mode,

        @NotNull(message = "Scope acknowledgment must not be null")
        Boolean scopeAcknowledged,

        @NotBlank(message = "Scope acknowledgment version must not be blank")
        @Size(max = 20, message = "Scope acknowledgment version must not exceed 20 characters")
        String scopeAckVersion
) {
}
