package com.ospysin.llm.parser;

public record LlmCommentParsedResult(
        String comment,
        String suggestedTool,
        String suggestedReason
) {}
