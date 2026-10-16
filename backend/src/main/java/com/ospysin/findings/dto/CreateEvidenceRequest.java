package com.ospysin.findings.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record CreateEvidenceRequest(
        @NotNull UUID resultId,
        @NotBlank @Size(max = 5000) String snippet
) {
}
