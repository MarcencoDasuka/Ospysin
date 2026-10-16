package com.ospysin.findings.dto;

import com.ospysin.findings.FindingConfidence;
import com.ospysin.findings.FindingSeverity;
import com.ospysin.findings.FindingStatus;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public record FindingResponse(
        UUID id,
        UUID sessionId,
        UUID observationId,
        String title,
        String description,
        FindingSeverity severity,
        FindingConfidence confidence,
        FindingStatus status,
        String rejectionReason,
        String remediation,
        List<EvidenceResponse> evidence,
        Instant createdAt,
        Instant updatedAt
) {
    public FindingResponse {
        evidence = evidence != null ? List.copyOf(evidence) : Collections.emptyList();
    }
}
