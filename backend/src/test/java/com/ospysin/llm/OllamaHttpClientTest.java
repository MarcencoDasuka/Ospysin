package com.ospysin.llm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.ospysin.llm.client.LlmClientException;
import com.ospysin.llm.client.OllamaHttpClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OllamaHttpClientTest {

    private WireMockServer wireMockServer;
    private OllamaHttpClient client;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();

        objectMapper = new ObjectMapper();
        client = new OllamaHttpClient(
                wireMockServer.baseUrl(),
                "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M",
                5,
                objectMapper,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()
        );
    }

    @AfterEach
    void tearDown() {
        if (wireMockServer != null && wireMockServer.isRunning()) {
            wireMockServer.stop();
        }
    }

    @Test
    @DisplayName("generateCommentJson sends expected Ollama payload with format=json and extracts content")
    void testGenerateCommentJson() {
        String expectedContent = "{\"comment\": \"HSTS enforced, missing CSP\", \"suggested_tool\": \"tls_info\", \"suggested_reason\": \"Verify TLS\"}";
        String responseJson = """
                {
                  "model": "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M",
                  "created_at": "2026-10-15T12:00:00Z",
                  "message": {
                    "role": "assistant",
                    "content": "%s"
                  },
                  "done": true
                }
                """.formatted(expectedContent.replace("\"", "\\\""));

        wireMockServer.stubFor(post(urlEqualTo("/api/chat"))
                .withHeader("Content-Type", containing("application/json"))
                .withRequestBody(matchingJsonPath("$.model", equalTo("hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M")))
                .withRequestBody(matchingJsonPath("$.format", equalTo("json")))
                .withRequestBody(matchingJsonPath("$.options.num_ctx", equalTo("2048")))
                .withRequestBody(matchingJsonPath("$.options.num_predict", equalTo("512")))
                .withRequestBody(matchingJsonPath("$.messages[0].role", equalTo("system")))
                .withRequestBody(matchingJsonPath("$.messages[1].role", equalTo("user")))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(responseJson)));

        String result = client.generateCommentJson("System instructions", "User context");

        assertThat(result).isEqualTo(expectedContent);
        wireMockServer.verify(postRequestedFor(urlEqualTo("/api/chat")));
    }

    @Test
    @DisplayName("generateChatReply sends request without format=json and extracts assistant reply")
    void testGenerateChatReply() {
        String responseJson = """
                {
                  "model": "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M",
                  "message": {
                    "role": "assistant",
                    "content": "A Content-Security-Policy header defines trusted script sources."
                  },
                  "done": true
                }
                """;

        wireMockServer.stubFor(post(urlEqualTo("/api/chat"))
                .withRequestBody(matchingJsonPath("$.model", equalTo("hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M")))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(responseJson)));

        String result = client.generateChatReply("System chat instructions", "What is CSP?");

        assertThat(result).isEqualTo("A Content-Security-Policy header defines trusted script sources.");
    }

    @Test
    @DisplayName("Throws LlmClientException when Ollama returns non-200 status code")
    void testNon200Response() {
        wireMockServer.stubFor(post(urlEqualTo("/api/chat"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withBody("Internal server error in Ollama engine")));

        assertThatThrownBy(() -> client.generateCommentJson("System", "User"))
                .isInstanceOf(LlmClientException.class)
                .hasMessageContaining("Ollama returned HTTP 500");
    }

    @Test
    @DisplayName("Throws LlmClientException when Ollama is unreachable")
    void testOllamaUnreachable() {
        wireMockServer.stop();

        assertThatThrownBy(() -> client.generateCommentJson("System", "User"))
                .isInstanceOf(LlmClientException.class)
                .hasMessageContaining("Failed to communicate with Ollama");
    }

    @Test
    @DisplayName("Throws LlmClientException when response body is missing message.content")
    void testMissingMessageContent() {
        wireMockServer.stubFor(post(urlEqualTo("/api/chat"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"model\": \"test\", \"done\": true}")));

        assertThatThrownBy(() -> client.generateCommentJson("System", "User"))
                .isInstanceOf(LlmClientException.class)
                .hasMessageContaining("missing message.content");
    }
}
