package com.ospysin.shared.health;

import java.util.Map;

public record HealthResponse(
        String status,
        Map<String, String> components
) {
}
