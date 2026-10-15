package com.ospysin.tools.probes;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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

class ExtractJsUrlsToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static ExtractJsUrlsTool tool;
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

        PinnedHttpClient pinnedHttpClient = new PinnedHttpClient(policyEngine);
        tool = new ExtractJsUrlsTool(pinnedHttpClient, policyEngine);

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

    @Test
    @DisplayName("Extracts external/internal scripts, evaluates SRI integrity, and uncovers inline API endpoints")
    void extractsScriptsAndDiscoversEndpoints() throws Exception {
        String html = """
                <!DOCTYPE html>
                <html>
                <head>
                  <title>Script Test Page</title>
                  <script src="/static/app.bundle.js"></script>
                  <script src="https://cdn.example.org/lib.js" integrity="sha384-xyz123"></script>
                  <script src="https://untrusted-cdn.com/analytics.js"></script>
                </head>
                <body>
                  <h1>Welcome</h1>
                  <script>
                    const endpoint = "/api/v1/auth/login";
                    function fetchUsers() {
                        return fetch("/api/v2/users/list");
                    }
                    const graphqlUrl = "/graphql";
                    const adminPath = "/admin/dashboard";
                  </script>
                  <script>
                    console.log("No endpoints here");
                  </script>
                </body>
                </html>
                """;

        stubFor(get(urlEqualTo("/app"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody(html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/app";
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
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scripts = (List<Map<String, Object>>) data.get("scripts");
        assertThat(scripts).hasSize(3);

        // Internal script
        Map<String, Object> internalScript = scripts.stream()
                .filter(s -> s.get("src").equals("http://127.0.0.1:" + wireMockPort + "/static/app.bundle.js"))
                .findFirst().orElseThrow();
        assertThat(internalScript.get("isInternal")).isEqualTo(true);
        assertThat(internalScript.get("hasIntegrity")).isEqualTo(false);

        // External script with integrity
        Map<String, Object> cdnScript = scripts.stream()
                .filter(s -> s.get("src").equals("https://cdn.example.org/lib.js"))
                .findFirst().orElseThrow();
        assertThat(cdnScript.get("isInternal")).isEqualTo(false);
        assertThat(cdnScript.get("hasIntegrity")).isEqualTo(true);

        // External script without integrity
        Map<String, Object> untrustedScript = scripts.stream()
                .filter(s -> s.get("src").equals("https://untrusted-cdn.com/analytics.js"))
                .findFirst().orElseThrow();
        assertThat(untrustedScript.get("isInternal")).isEqualTo(false);
        assertThat(untrustedScript.get("hasIntegrity")).isEqualTo(false);

        // Inline scripts count
        assertThat(data.get("inlineScriptsCount")).isEqualTo(2);

        @SuppressWarnings("unchecked")
        List<String> discoveredEndpoints = (List<String>) data.get("discoveredEndpoints");
        assertThat(discoveredEndpoints).contains(
                "/api/v1/auth/login",
                "/api/v2/users/list",
                "/graphql",
                "/admin/dashboard"
        );

        // Observations: external script without SRI + discovered endpoints
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(2);

        assertThat(observations).anyMatch(obs -> obs.category().equals("SCRIPT_SECURITY")
                && obs.severityHeuristic() == SeverityHeuristic.LOW
                && obs.description().contains("https://untrusted-cdn.com/analytics.js"));

        assertThat(observations).anyMatch(obs -> obs.category().equals("RECON_ENDPOINTS")
                && obs.severityHeuristic() == SeverityHeuristic.INFO
                && obs.description().contains("/api/v1/auth/login")
                && obs.description().contains("/graphql"));
    }

    @Test
    @DisplayName("P14-01 Regression: Filters non-HTTP script schemes and handles complex query strings in host extraction")
    void ignoresNonHttpSchemesAndExtractsHostWithComplexQuery() throws Exception {
        String html = """
                <!DOCTYPE html>
                <html>
                <head>
                  <script src="javascript:alert(1)"></script>
                  <script src="data:text/javascript,console.log('hi')"></script>
                  <script src="blob:http://127.0.0.1:%d/12345"></script>
                  <script src="mailto:admin@example.com"></script>
                  <script src="https://cdn.example.org/bundle.js?v=1|2"></script>
                  <script src="http://127.0.0.1:%d/valid.js"></script>
                </head>
                <body>
                  <h1>Script Scheme Test</h1>
                </body>
                </html>
                """.formatted(wireMockPort, wireMockPort);

        stubFor(get(urlEqualTo("/schemes"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody(html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/schemes";
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

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scripts = (List<Map<String, Object>>) outcome.parsedData().get("scripts");
        assertThat(scripts).hasSize(2);

        assertThat(scripts).noneMatch(s -> ((String) s.get("src")).startsWith("javascript:")
                || ((String) s.get("src")).startsWith("data:")
                || ((String) s.get("src")).startsWith("blob:")
                || ((String) s.get("src")).startsWith("mailto:"));

        Map<String, Object> externalScript = scripts.stream()
                .filter(s -> s.get("src").equals("https://cdn.example.org/bundle.js?v=1|2"))
                .findFirst().orElseThrow();
        assertThat(externalScript.get("isInternal")).isEqualTo(false);
        assertThat(externalScript.get("hasIntegrity")).isEqualTo(false);

        Map<String, Object> internalScript = scripts.stream()
                .filter(s -> s.get("src").equals("http://127.0.0.1:" + wireMockPort + "/valid.js"))
                .findFirst().orElseThrow();
        assertThat(internalScript.get("isInternal")).isEqualTo(true);

        // SRI observation should only be emitted for the valid external script
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("SCRIPT_SECURITY");
        assertThat(observations.get(0).description()).contains("https://cdn.example.org/bundle.js?v=1|2");
    }

    @Test
    @DisplayName("P14-01 Regression: Parses non-200 responses when body is non-empty and reports status code")
    void parsesNon200ResponseWithBody() throws Exception {
        String errorHtml = """
                <!DOCTYPE html>
                <html>
                <head>
                  <title>401 Unauthorized</title>
                  <script src="/static/login-prompt.js"></script>
                </head>
                <body>
                  <h1>Please Sign In</h1>
                  <script>
                    const authApi = "/api/v1/auth/token";
                  </script>
                </body>
                </html>
                """;

        stubFor(get(urlEqualTo("/protected"))
                .willReturn(aResponse()
                        .withStatus(401)
                        .withHeader("Content-Type", "text/html")
                        .withBody(errorHtml)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/protected";
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
        assertThat(data.get("statusCode")).isEqualTo(401);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> scripts = (List<Map<String, Object>>) data.get("scripts");
        assertThat(scripts).hasSize(1);
        assertThat(scripts.get(0).get("src")).isEqualTo("http://127.0.0.1:" + wireMockPort + "/static/login-prompt.js");

        @SuppressWarnings("unchecked")
        List<String> discoveredEndpoints = (List<String>) data.get("discoveredEndpoints");
        assertThat(discoveredEndpoints).contains("/api/v1/auth/token");
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
