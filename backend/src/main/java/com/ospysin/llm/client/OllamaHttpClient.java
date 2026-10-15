package com.ospysin.llm.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * HTTP client for local Ollama service communicating via /api/chat.
 */
@Slf4j
@Component
public class OllamaHttpClient implements LlmClient {

    private final String baseUrl;
    private final String model;
    private final int timeoutSeconds;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Autowired
    public OllamaHttpClient(
            @Value("${ospysin.ollama.base-url:http://127.0.0.1:11434}") String baseUrl,
            @Value("${ospysin.ollama.model:hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M}") String model,
            @Value("${ospysin.ollama.timeout-seconds:60}") int timeoutSeconds,
            ObjectMapper objectMapper
    ) {
        this(baseUrl, model, timeoutSeconds, objectMapper,
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(10))
                        .build()
        );
    }

    public OllamaHttpClient(
            String baseUrl,
            String model,
            int timeoutSeconds,
            ObjectMapper objectMapper,
            HttpClient httpClient
    ) {
        this.baseUrl = normalizeBaseUrl(baseUrl);
        this.model = Objects.requireNonNull(model, "model must not be null");
        this.timeoutSeconds = timeoutSeconds > 0 ? timeoutSeconds : 60;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
    }

    @Override
    public String generateCommentJson(String systemPrompt, String userPrompt) {
        return invokeChatApi(systemPrompt, userPrompt, true);
    }

    @Override
    public String generateChatReply(String systemPrompt, String userPrompt) {
        return invokeChatApi(systemPrompt, userPrompt, false);
    }

    private String invokeChatApi(String systemPrompt, String userPrompt, boolean jsonFormat) {
        try {
            Map<String, Object> requestMap = new LinkedHashMap<>();
            requestMap.put("model", model);
            if (jsonFormat) {
                requestMap.put("format", "json");
            }
            requestMap.put("stream", false);

            Map<String, Object> options = new LinkedHashMap<>();
            options.put("num_ctx", 2048);
            options.put("temperature", 0.1);
            options.put("top_p", 0.9);
            options.put("num_predict", 512);
            requestMap.put("options", options);

            List<Map<String, String>> messages = List.of(
                    Map.of("role", "system", "content", systemPrompt != null ? systemPrompt : ""),
                    Map.of("role", "user", "content", userPrompt != null ? userPrompt : "")
            );
            requestMap.put("messages", messages);

            String requestBody = objectMapper.writeValueAsString(requestMap);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/chat"))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode contentNode = root.path("message").path("content");
                if (contentNode.isMissingNode() || contentNode.isNull()) {
                    throw new LlmClientException("Ollama response missing message.content: " + response.body());
                }
                return contentNode.asText();
            } else {
                throw new LlmClientException("Ollama returned HTTP " + response.statusCode() + ": " + response.body());
            }
        } catch (IOException ex) {
            log.warn("Ollama HTTP I/O failure: {}", ex.getMessage());
            throw new LlmClientException("Failed to communicate with Ollama: " + ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new LlmClientException("Ollama request interrupted", ex);
        }
    }

    private static String normalizeBaseUrl(String url) {
        if (url == null || url.isBlank()) {
            return "http://127.0.0.1:11434";
        }
        return url.replaceAll("/+$", "");
    }
}
