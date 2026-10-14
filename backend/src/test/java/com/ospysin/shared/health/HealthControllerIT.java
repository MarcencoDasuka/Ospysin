package com.ospysin.shared.health;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.ospysin.AbstractIntegrationTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;

class HealthControllerIT extends AbstractIntegrationTest {

    private static WireMockServer wireMockServer;

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @BeforeAll
    static void startWireMock() {
        wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();
        WireMock.configureFor("127.0.0.1", wireMockServer.port());

        // Stub Ollama /api/tags
        wireMockServer.stubFor(get(urlEqualTo("/api/tags"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "models": [
                                    { "name": "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M" }
                                  ]
                                }
                                """)));
    }

    @AfterAll
    static void stopWireMock() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @DynamicPropertySource
    static void configureOllamaMock(DynamicPropertyRegistry registry) {
        registry.add("ospysin.ollama.base-url", () -> "http://127.0.0.1:" + wireMockServer.port());
    }

    @Test
    @DisplayName("GET /api/health returns 200 OK with database UP and ollama UP when reachable")
    void shouldReturnHealthUpWithComponents() {
        ResponseEntity<HealthResponse> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/api/health",
                HealthResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo("UP");
        assertThat(response.getBody().components()).containsEntry("database", "UP");
        assertThat(response.getBody().components()).containsEntry("ollama", "UP");
    }

    @Test
    @DisplayName("GET /api/health returns 200 OK with database UP and advisory ollama DOWN when Ollama fails")
    void shouldReturnHealthUpWithOllamaDownWhenUnreachable() {
        wireMockServer.stubFor(get(urlEqualTo("/api/tags"))
                .willReturn(aResponse().withStatus(500)));

        try {
            ResponseEntity<HealthResponse> response = restTemplate.getForEntity(
                    "http://localhost:" + port + "/api/health",
                    HealthResponse.class
            );

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().status()).isEqualTo("UP");
            assertThat(response.getBody().components()).containsEntry("database", "UP");
            assertThat(response.getBody().components()).containsEntry("ollama", "DOWN");
        } finally {
            wireMockServer.stubFor(get(urlEqualTo("/api/tags"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json")
                            .withBody("""
                                    {
                                      "models": [
                                        { "name": "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M" }
                                      ]
                                    }
                                    """)));
        }
    }
}
