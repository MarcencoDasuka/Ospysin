package com.ospysin.findings.dto;

import com.ospysin.findings.FindingConfidence;
import com.ospysin.findings.FindingSeverity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record CreateFindingRequest(
        UUID observationId,
        @NotBlank @Size(max = 200) String title,
        @NotBlank @Size(max = 10000) String description,
        @NotNull FindingSeverity severity,
        FindingConfidence confidence,
        @Size(max = 10000) String remediation
) {
}
