package com.ospysin.llm.dto;

public record CommentContextSnapshot(
        SessionContextSnapshot sessionSnapshot,
        StepContextSnapshot stepSnapshot
) {}
