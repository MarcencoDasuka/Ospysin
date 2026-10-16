package com.ospysin.tools.probes;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.ospysin.execution.HostRateLimiter;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SensitiveFilesCheckToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static HostRateLimiter hostRateLimiter;
    private static SensitiveFilesCheckTool tool;
    private static ScopeAsset localScopeAsset;

    @BeforeAll
    static void setUpAll() {
        wireMockPort = findFreeAllowedPort();
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(wireMockPort));
        wireMockServer.start();
        WireMock.configureFor("127.0.0.1", wireMockPort);

        Clock clock = Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        IpRangeValidator ipRangeValidator = new IpRangeValidator();
        policyEngine = new PolicyEngine(ipRangeValidator, host -> new InetAddress[]{InetAddress.getByName(host)}, clock);

        hostRateLimiter = Mockito.mock(HostRateLimiter.class);
        PinnedHttpClient pinnedHttpClient = new PinnedHttpClient(policyEngine);
        tool = new SensitiveFilesCheckTool(pinnedHttpClient, policyEngine, hostRateLimiter);

        localScopeAsset = ScopeAsset.builder()
                .assetType(AssetType.IP)
                .value("127.0.0.1")
                .isWildcard(false)
                .build();
    }

    @AfterAll
    static void tearDownAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @BeforeEach
    void resetWireMock() {
        wireMockServer.resetAll();
        Mockito.reset(hostRateLimiter);
    }

    @Test
    @DisplayName("validateParams rejects invalid customPaths (traversal, missing leading slash, double slash, CRLF)")
    void validateParamsRejectsInvalidCustomPaths() {
        // Missing leading slash
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", List.of("bad/path"))))
                .isInstanceOf(ValidationException.class);

        // Path traversal ..
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", List.of("/../secret"))))
                .isInstanceOf(ValidationException.class);

        // Double slash //
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", List.of("//secret"))))
                .isInstanceOf(ValidationException.class);

        // Backslash \
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", List.of("/path\\secret"))))
                .isInstanceOf(ValidationException.class);

        // CRLF
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", List.of("/path\r\n"))))
                .isInstanceOf(ValidationException.class);

        // Scheme prefix ://
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", List.of("/http://evil.com"))))
                .isInstanceOf(ValidationException.class);

        // More than 20 paths
        List<String> tooMany = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            tooMany.add("/path" + i);
        }
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPaths", tooMany)))
                .isInstanceOf(ValidationException.class);

        // Non-boolean stopOnFirstExposed
        assertThatThrownBy(() -> tool.validateParams(Map.of("stopOnFirstExposed", "yes")))
                .isInstanceOf(ValidationException.class);

        // Explicit null customPaths
        Map<String, Object> nullCustomPaths = new HashMap<>();
        nullCustomPaths.put("customPaths", null);
        assertThatThrownBy(() -> tool.validateParams(nullCustomPaths))
                .isInstanceOf(ValidationException.class);

        // Explicit null stopOnFirstExposed
        Map<String, Object> nullStopOnFirstExposed = new HashMap<>();
        nullStopOnFirstExposed.put("stopOnFirstExposed", null);
        assertThatThrownBy(() -> tool.validateParams(nullStopOnFirstExposed))
                .isInstanceOf(ValidationException.class);

        // Valid parameters accepted
        tool.validateParams(Map.of("customPaths", List.of("/api/secret", "/internal.json"), "stopOnFirstExposed", true));
        tool.validateParams(Collections.emptyMap());
    }

    @Test
    @DisplayName("Soft-404 rejection: Server returns 200 OK with HTML Not Found page -> exposedCount == 0")
    void rejectsSoft404HtmlPages() throws Exception {
        String soft404Html = """
                <!DOCTYPE html>
                <html>
                <head><title>Not Found</title></head>
                <body>
                  <h1>404 Not Found</h1>
                  <p>The requested page could not be found on this server.</p>
                </body>
                </html>
                """;

        stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html; charset=utf-8")
                        .withBody(soft404Html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of(),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.score()).isNull();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("exposedCount")).isEqualTo(0);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exposedFiles = (List<Map<String, Object>>) data.get("exposedFiles");
        assertThat(exposedFiles).isEmpty();
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("True positive detection & secret redaction: exposes .env, .git/HEAD, actuator/env, backup.zip with masked secrets")
    void truePositiveDetectionAndRedaction() throws Exception {
        stubFor(get(anyUrl())
                .willReturn(aResponse().withStatus(404).withBody("Not Found")));

        stubFor(get(urlEqualTo("/.env"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody("DB_HOST=127.0.0.1\nDB_USER=admin\nDB_PASSWORD=supersecret_pass123\nAPI_KEY=" + ("sk_live_" + "verysecret"))));

        stubFor(get(urlEqualTo("/.git/HEAD"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody("ref: refs/heads/main\n")));

        stubFor(get(urlEqualTo("/actuator/env"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"propertySources\": [{\"name\": \"systemEnvironment\"}]}")));

        stubFor(get(urlEqualTo("/backup.zip"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/zip")
                        .withBody(new byte[]{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x08, 0x00})));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of(),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("exposedCount")).isEqualTo(4);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exposedFiles = (List<Map<String, Object>>) data.get("exposedFiles");
        assertThat(exposedFiles).hasSize(4);

        Map<String, Object> envEntry = exposedFiles.stream()
                .filter(f -> "/.env".equals(f.get("path")))
                .findFirst().orElseThrow();
        assertThat(envEntry.get("confidence")).isEqualTo("HIGH");
        assertThat(envEntry.get("severity")).isEqualTo("CRITICAL");
        String envSnippet = (String) envEntry.get("snippet");
        assertThat(envSnippet).contains("DB_PASSWORD=***");
        assertThat(envSnippet).contains("API_KEY=***");
        assertThat(envSnippet).doesNotContain("supersecret_pass123");
        assertThat(envSnippet).doesNotContain("sk_live_" + "verysecret");

        Map<String, Object> zipEntry = exposedFiles.stream()
                .filter(f -> "/backup.zip".equals(f.get("path")))
                .findFirst().orElseThrow();
        assertThat(zipEntry.get("snippet")).isEqualTo("[Binary payload: 8 bytes]");

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(4);
        assertThat(observations).allMatch(o -> "SENSITIVE_FILE_EXPOSED".equals(o.category()));
        assertThat(observations).anyMatch(o -> o.description().contains("/.env") && o.severityHeuristic() == SeverityHeuristic.HIGH);

        Mockito.verify(hostRateLimiter, Mockito.atLeastOnce()).acquire(Mockito.anyString());
    }

    @Test
    @DisplayName("stopOnFirstExposed = true stops after first exposed finding")
    void stopOnFirstExposedStopsImmediately() throws Exception {
        stubFor(get(anyUrl())
                .willReturn(aResponse().withStatus(404)));

        stubFor(get(urlEqualTo("/.env"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("APP_ENV=production\nAPP_KEY=secret_key")));

        stubFor(get(urlEqualTo("/.git/HEAD"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("ref: refs/heads/main\n")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("stopOnFirstExposed", true),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("exposedCount")).isEqualTo(1);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exposedFiles = (List<Map<String, Object>>) data.get("exposedFiles");
        assertThat(exposedFiles).hasSize(1);
        assertThat(exposedFiles.get(0).get("path")).isEqualTo("/.env");
    }

    @Test
    @DisplayName("Custom paths checking detects exposed non-HTML content with MEDIUM confidence")
    void checksCustomPathsWithMediumConfidence() throws Exception {
        stubFor(get(anyUrl())
                .willReturn(aResponse().withStatus(404)));

        stubFor(get(urlEqualTo("/private/config.txt"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody("Internal routing table configuration")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPaths", List.of("/private/config.txt")),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> exposedFiles = (List<Map<String, Object>>) outcome.parsedData().get("exposedFiles");
        assertThat(exposedFiles).hasSize(1);
        assertThat(exposedFiles.get(0).get("path")).isEqualTo("/private/config.txt");
        assertThat(exposedFiles.get(0).get("confidence")).isEqualTo("MEDIUM");
        assertThat(exposedFiles.get(0).get("severity")).isEqualTo("MEDIUM");
    }

    private static int findFreeAllowedPort() {
        for (int port : List.of(8080, 8443, 8000, 3000, 5000)) {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress("127.0.0.1", port));
                return port;
            } catch (IOException ignored) {
            }
        }
        throw new IllegalStateException("No allowed test port free");
    }
}
