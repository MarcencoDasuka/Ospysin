package com.ospysin.sessions.dto;

import java.util.List;

public record SessionPageResponse(
        List<SessionResponse> content,
        int page,
        int size,
        long totalElements,
        int totalPages
) {
}
