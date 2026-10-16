package com.ospysin.findings.dto;

import com.ospysin.findings.FindingConfidence;
import com.ospysin.findings.FindingSeverity;
import com.ospysin.findings.FindingStatus;
import jakarta.validation.constraints.Size;

public record UpdateFindingRequest(
        @Size(max = 200) String title,
        @Size(max = 10000) String description,
        FindingSeverity severity,
        FindingConfidence confidence,
        FindingStatus status,
        @Size(max = 2000) String rejectionReason,
        @Size(max = 10000) String remediation
) {
}
