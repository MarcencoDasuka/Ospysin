package com.ospysin.findings.dto;

import java.time.Instant;
import java.util.UUID;

public record EvidenceResponse(
        UUID id,
        UUID findingId,
        UUID resultId,
        UUID executionId,
        String toolId,
        String snippet,
        Instant createdAt
) {
}
