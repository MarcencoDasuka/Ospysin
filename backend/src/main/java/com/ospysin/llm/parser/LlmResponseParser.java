package com.ospysin.llm.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.tools.ToolCatalogRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Ollama Comment Mode responses, validates suggested tools against the
 * 15-tool catalog, and falls back gracefully on malformed or non-JSON output.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class LlmResponseParser {

    private static final Pattern CODE_BLOCK_PATTERN = Pattern.compile("^```(?:json)?\\s*([\\s\\S]*?)\\s*```$", Pattern.CASE_INSENSITIVE);

    private final ObjectMapper objectMapper;
    private final ToolCatalogRegistry toolCatalogRegistry;

    public LlmCommentParsedResult parseComment(String rawResponse, String currentToolId) {
        if (rawResponse == null || rawResponse.isBlank()) {
            return new LlmCommentParsedResult("No analysis provided by advisor.", null, null);
        }

        String cleaned = rawResponse.trim();
        Matcher matcher = CODE_BLOCK_PATTERN.matcher(cleaned);
        if (matcher.find()) {
            cleaned = matcher.group(1).trim();
        }

        try {
            JsonNode root = objectMapper.readTree(cleaned);
            if (root.isObject()) {
                String comment = root.path("comment").asText(null);
                if (comment == null || comment.isBlank()) {
                    comment = cleaned;
                }

                String suggestedTool = null;
                JsonNode toolNode = root.path("suggested_tool");
                if (!toolNode.isMissingNode() && !toolNode.isNull()) {
                    String candidate = toolNode.asText().trim();
                    if (!candidate.isBlank() && !"null".equalsIgnoreCase(candidate)) {
                        if (toolCatalogRegistry.isRegistered(candidate)) {
                            suggestedTool = candidate;
                        } else {
                            log.warn("Discarding unknown or hallucinated suggested tool '{}' for tool '{}'", candidate, currentToolId);
                        }
                    }
                }

                String suggestedReason = null;
                if (suggestedTool != null) {
                    JsonNode reasonNode = root.path("suggested_reason");
                    if (!reasonNode.isMissingNode() && !reasonNode.isNull()) {
                        String r = reasonNode.asText().trim();
                        if (!r.isBlank() && !"null".equalsIgnoreCase(r)) {
                            suggestedReason = r;
                        }
                    }
                }

                return new LlmCommentParsedResult(comment, suggestedTool, suggestedReason);
            }
        } catch (Exception ex) {
            log.warn("Ollama returned non-JSON text in Comment Mode. Falling back gracefully: {}", ex.getMessage());
        }

        // Graceful fallback for non-JSON text
        return new LlmCommentParsedResult(rawResponse.trim(), null, null);
    }
}
