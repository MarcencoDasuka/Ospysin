package com.ospysin.shared.health;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/health")
public class HealthController {

    private final DataSource dataSource;
    private final String ollamaBaseUrl;
    private final HttpClient httpClient;

    public HealthController(
            DataSource dataSource,
            @Value("${ospysin.ollama.base-url:http://127.0.0.1:11434}") String ollamaBaseUrl
    ) {
        this.dataSource = dataSource;
        this.ollamaBaseUrl = ollamaBaseUrl != null ? ollamaBaseUrl.replaceAll("/+$", "") : "http://127.0.0.1:11434";
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(1500))
                .build();
    }

    @GetMapping
    public ResponseEntity<HealthResponse> getHealth() {
        String dbStatus = checkDatabase();
        String ollamaStatus = checkOllama();

        Map<String, String> components = new LinkedHashMap<>();
        components.put("database", dbStatus);
        components.put("ollama", ollamaStatus);

        // Per docs/06-LLM-INTEGRATION.md, Ollama absence does not degrade backend health to DOWN
        String overallStatus = "UP".equals(dbStatus) ? "UP" : "DOWN";

        HealthResponse response = new HealthResponse(overallStatus, components);
        return ResponseEntity.ok(response);
    }

    private String checkDatabase() {
        try (Connection connection = dataSource.getConnection()) {
            return connection.isValid(2) ? "UP" : "DOWN";
        } catch (Exception ex) {
            log.warn("Health check: database connectivity failure - {}", ex.getMessage());
            return "DOWN";
        }
    }

    private String checkOllama() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ollamaBaseUrl + "/api/tags"))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();

            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            return (response.statusCode() >= 200 && response.statusCode() < 300) ? "UP" : "DOWN";
        } catch (Exception ex) {
            log.debug("Health check: Ollama is unreachable at {} (advisory only): {}", ollamaBaseUrl, ex.getMessage());
            return "DOWN";
        }
    }
}
