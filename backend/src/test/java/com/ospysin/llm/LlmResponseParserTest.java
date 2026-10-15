package com.ospysin.llm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.llm.parser.LlmCommentParsedResult;
import com.ospysin.llm.parser.LlmResponseParser;
import com.ospysin.tools.ToolCatalogRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class LlmResponseParserTest {

    private LlmResponseParser parser;
    private ToolCatalogRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ToolCatalogRegistry(Collections.emptyList());
        parser = new LlmResponseParser(new ObjectMapper(), registry);
    }

    @Test
    @DisplayName("Parses valid JSON and accepts registered tool")
    void testParseValidJsonWithRegisteredTool() {
        String json = """
                {
                  "comment": "The server enforces Strict-Transport-Security but lacks Content-Security-Policy (CSP).",
                  "suggested_tool": "tls_info",
                  "suggested_reason": "Inspect TLS configuration to verify certificate validity and cipher suites."
                }
                """;

        LlmCommentParsedResult result = parser.parseComment(json, "http_headers");

        assertThat(result.comment()).contains("Strict-Transport-Security");
        assertThat(result.suggestedTool()).isEqualTo("tls_info");
        assertThat(result.suggestedReason()).isEqualTo("Inspect TLS configuration to verify certificate validity and cipher suites.");
    }

    @Test
    @DisplayName("Sanitizes hallucinated tool to null while retaining comment")
    void testSanitizeHallucinatedTool() {
        String json = """
                {
                  "comment": "Potential SQL injection vulnerability detected on the login endpoint.",
                  "suggested_tool": "sqlmap",
                  "suggested_reason": "Run automated SQL injection exploitation."
                }
                """;

        LlmCommentParsedResult result = parser.parseComment(json, "http_headers");

        assertThat(result.comment()).contains("Potential SQL injection");
        assertThat(result.suggestedTool()).isNull();
        assertThat(result.suggestedReason()).isNull();
    }

    @Test
    @DisplayName("Handles null or explicit null string suggested_tool gracefully")
    void testNullSuggestedTool() {
        String json = """
                {
                  "comment": "All standard security headers are correctly configured.",
                  "suggested_tool": null,
                  "suggested_reason": null
                }
                """;

        LlmCommentParsedResult result = parser.parseComment(json, "http_headers");

        assertThat(result.comment()).contains("All standard security headers");
        assertThat(result.suggestedTool()).isNull();
        assertThat(result.suggestedReason()).isNull();
    }

    @Test
    @DisplayName("Strips Markdown code blocks before parsing JSON")
    void testMarkdownCodeBlockParsing() {
        String markdown = """
                ```json
                {
                  "comment": "Missing X-Content-Type-Options header.",
                  "suggested_tool": "robots_txt",
                  "suggested_reason": "Check robots.txt for hidden paths."
                }
                ```
                """;

        LlmCommentParsedResult result = parser.parseComment(markdown, "http_headers");

        assertThat(result.comment()).isEqualTo("Missing X-Content-Type-Options header.");
        assertThat(result.suggestedTool()).isEqualTo("robots_txt");
        assertThat(result.suggestedReason()).isEqualTo("Check robots.txt for hidden paths.");
    }

    @Test
    @DisplayName("Falls back gracefully to raw text when response is malformed or non-JSON")
    void testMalformedJsonFallback() {
        String rawText = "Based on my analysis, the target host has several missing headers including CSP and HSTS. I recommend checking the certificate.";

        LlmCommentParsedResult result = parser.parseComment(rawText, "http_headers");

        assertThat(result.comment()).isEqualTo(rawText);
        assertThat(result.suggestedTool()).isNull();
        assertThat(result.suggestedReason()).isNull();
    }

    @Test
    @DisplayName("Handles empty or null response gracefully")
    void testEmptyResponse() {
        LlmCommentParsedResult result = parser.parseComment(null, "http_headers");
        assertThat(result.comment()).isNotBlank();
        assertThat(result.suggestedTool()).isNull();

        LlmCommentParsedResult emptyResult = parser.parseComment("   ", "http_headers");
        assertThat(emptyResult.comment()).isNotBlank();
        assertThat(emptyResult.suggestedTool()).isNull();
    }
}
