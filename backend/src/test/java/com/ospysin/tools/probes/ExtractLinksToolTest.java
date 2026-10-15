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
import com.ospysin.shared.error.ValidationException;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExtractLinksToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static ExtractLinksTool tool;
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
        tool = new ExtractLinksTool(pinnedHttpClient, policyEngine);

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
    @DisplayName("validateParams rejects maxLinks out of range 1..5000")
    void validateParamsRejectsInvalidMaxLinks() {
        assertThatThrownBy(() -> tool.validateParams(Map.of("maxLinks", 0)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> assertThat(((ValidationException) ex).getInvalidParams())
                        .extracting(ip -> ip.name()).contains("maxLinks"));

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxLinks", 5001)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxLinks", -5)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Collections.singletonMap("maxLinks", null)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> assertThat(((ValidationException) ex).getInvalidParams())
                        .extracting(ip -> ip.name()).contains("maxLinks"));

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxLinks", 20.5)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxLinks", 30.0f)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams accepts valid maxLinks and null/empty params")
    void validateParamsAcceptsValid() {
        tool.validateParams(Map.of("maxLinks", 1));
        tool.validateParams(Map.of("maxLinks", 200));
        tool.validateParams(Map.of("maxLinks", 5000));
        tool.validateParams(Collections.emptyMap());
        tool.validateParams(null);
    }

    @Test
    @DisplayName("Extracts internal and external links, resolves relative paths, and filters pseudo-schemes")
    void extractsAndSegregatesLinks() throws Exception {
        String html = """
                <!DOCTYPE html>
                <html>
                <head><title>Test Links</title></head>
                <body>
                  <nav>
                    <a href="/about">About Us</a>
                    <a href="/contact?ref=nav">Contact</a>
                    <a href="http://127.0.0.1:%d/docs/api">API Docs</a>
                    <a href="https://external-cdn.org/assets">External Asset</a>
                    <a href="https://github.com/project/ospysin">GitHub</a>
                    <a href="javascript:void(0)">Do Nothing</a>
                    <a href="mailto:security@example.com">Email Us</a>
                    <a href="tel:+123456789">Call Us</a>
                    <a href="#section">Anchor</a>
                  </nav>
                  <form action="/login" method="POST">
                    <input type="text" name="user"/>
                  </form>
                </body>
                </html>
                """.formatted(wireMockPort);

        stubFor(get(urlEqualTo("/index.html"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody(html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/index.html";
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("maxLinks", 50),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();

        @SuppressWarnings("unchecked")
        List<String> internalLinks = (List<String>) data.get("internalLinks");
        assertThat(internalLinks).contains(
                "http://127.0.0.1:" + wireMockPort + "/about",
                "http://127.0.0.1:" + wireMockPort + "/contact?ref=nav",
                "http://127.0.0.1:" + wireMockPort + "/docs/api"
        );
        assertThat(internalLinks).noneMatch(l -> l.contains("javascript:") || l.contains("mailto:") || l.contains("tel:"));

        @SuppressWarnings("unchecked")
        List<String> externalLinks = (List<String>) data.get("externalLinks");
        assertThat(externalLinks).contains(
                "https://external-cdn.org/assets",
                "https://github.com/project/ospysin"
        );

        @SuppressWarnings("unchecked")
        List<String> formActions = (List<String>) data.get("formActions");
        assertThat(formActions).contains("http://127.0.0.1:" + wireMockPort + "/login");

        assertThat(data.get("totalInternalCount")).isEqualTo(3);
        assertThat(data.get("totalExternalCount")).isEqualTo(2);
    }

    @Test
    @DisplayName("Detects insecure unencrypted HTTP form submission on HTTPS target")
    void detectsInsecureFormActionOnHttpsTarget() throws Exception {
        String html = """
                <!DOCTYPE html>
                <html>
                <body>
                  <form action="http://insecure-backend.com/submit-credentials" method="POST">
                    <input type="password" name="pwd"/>
                  </form>
                </body>
                </html>
                """;

        PinnedHttpClient mockClient = new PinnedHttpClient(policyEngine) {
            @Override
            public PinnedProbeResult executeWithRedirects(java.net.URI initialUri, InetAddress initialIp, boolean followRedirects,
                                                          SessionMode mode, ScopeAsset scopeAsset,
                                                          long maxWireBytes, long maxDecompressedBytes,
                                                          int readTimeoutMs) {
                return new PinnedProbeResult(
                        "https://example.com/checkout",
                        200,
                        "HTTP/1.1",
                        Map.of(),
                        List.of(),
                        List.of(),
                        "HTTP/1.1 200 OK\r\n\r\n" + html,
                        html.getBytes(java.nio.charset.StandardCharsets.UTF_8)
                );
            }
        };

        ExtractLinksTool httpsTool = new ExtractLinksTool(mockClient, policyEngine);
        ScopeAsset publicScope = ScopeAsset.builder().assetType(AssetType.FQDN).value("example.com").isWildcard(false).build();
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "https://example.com/checkout",
                SessionMode.PUBLIC,
                publicScope,
                Map.of(),
                new com.ospysin.policy.PolicyDecision(true, "ok", "example.com", InetAddress.getByName("93.184.216.34"), SessionMode.PUBLIC, 0)
        );

        ToolExecutionOutcome outcome = httpsTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("CONTENT_SECURITY");
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
        assertThat(observations.get(0).description()).contains("Form action submits data over unencrypted HTTP: http://insecure-backend.com/submit-credentials");
    }

    @Test
    @DisplayName("P14-01 Regression: Parses non-200 response bodies and records status code")
    void parsesNon200ResponseBodyAndExtractsLinks() throws Exception {
        String errorHtml = """
                <!DOCTYPE html>
                <html>
                <body>
                  <h1>403 Forbidden</h1>
                  <p>You do not have permission to view this resource.</p>
                  <a href="/login">Please log in</a>
                  <a href="https://support.example.com/tickets">Open a support ticket</a>
                </body>
                </html>
                """;

        stubFor(get(urlEqualTo("/forbidden"))
                .willReturn(aResponse()
                        .withStatus(403)
                        .withHeader("Content-Type", "text/html")
                        .withBody(errorHtml)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/forbidden";
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
        assertThat(data.get("statusCode")).isEqualTo(403);

        @SuppressWarnings("unchecked")
        List<String> internalLinks = (List<String>) data.get("internalLinks");
        assertThat(internalLinks).contains("http://127.0.0.1:" + wireMockPort + "/login");

        @SuppressWarnings("unchecked")
        List<String> externalLinks = (List<String>) data.get("externalLinks");
        assertThat(externalLinks).contains("https://support.example.com/tickets");
    }

    @Test
    @DisplayName("P14-01 Regression: extractHost normalizes trailing root dots and handles complex query parameters")
    void extractHostHandlesTrailingDotsAndComplexQuery() throws Exception {
        String html = """
                <!DOCTYPE html>
                <html>
                <body>
                  <a href="http://127.0.0.1.:%d/internal-path?filter=a|b">Internal</a>
                  <a href="https://external.org.:8443/docs?q=x|y#section">External</a>
                </body>
                </html>
                """.formatted(wireMockPort);

        stubFor(get(urlEqualTo("/dots"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody(html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/dots";
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

        @SuppressWarnings("unchecked")
        List<String> internalLinks = (List<String>) data.get("internalLinks");
        assertThat(internalLinks).contains("http://127.0.0.1.:" + wireMockPort + "/internal-path?filter=a|b");

        @SuppressWarnings("unchecked")
        List<String> externalLinks = (List<String>) data.get("externalLinks");
        assertThat(externalLinks).contains("https://external.org.:8443/docs?q=x|y#section");
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
