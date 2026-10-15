package com.ospysin.tools.probes;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPOutputStream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpHeadersToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static HttpHeadersTool tool;
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
        tool = new HttpHeadersTool(pinnedHttpClient, policyEngine);

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
    @DisplayName("validateParams rejects non-allowlisted customPort with 422 ValidationException")
    void validateParamsRejectsDisallowedPort() {
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPort", 22)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("customPort");
                });

        assertThatThrownBy(() -> tool.validateParams(Map.of("customPort", 25)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams accepts allowlisted ports and null or empty params")
    void validateParamsAcceptsAllowedPorts() {
        tool.validateParams(Map.of("customPort", 8080));
        tool.validateParams(Map.of("customPort", 8443));
        tool.validateParams(Map.of("customPort", 80));
        tool.validateParams(Map.of("customPort", 443));
        tool.validateParams(Collections.emptyMap());
        tool.validateParams(null);
    }

    @Test
    @DisplayName("Captures status, headers, cookies, server banners and generates security observations")
    void capturesHeadersAndGeneratesObservations() throws Exception {
        stubFor(get(urlEqualTo("/inspect"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Server", "Apache/2.4.41")
                        .withHeader("X-Powered-By", "PHP/8.1")
                        .withHeader("X-Content-Type-Options", "nosniff")
                        .withHeader("Set-Cookie", "SESSIONID=secret123; Path=/; Secure; HttpOnly; SameSite=Strict")
                        .withHeader("Set-Cookie", "tracker_id=abc; Path=/")
                        .withBody("OK")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/inspect";
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

        // Verification of architectural invariant: score must be null
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.rawOutput()).contains("HTTP/1.1 200").contains("Server: Apache/2.4.41");

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("statusCode")).isEqualTo(200);
        assertThat(data.get("finalUrl")).isEqualTo(targetUrl);
        assertThat(data.get("serverBanner")).isEqualTo("Apache/2.4.41");

        @SuppressWarnings("unchecked")
        Map<String, Object> headers = (Map<String, Object>) data.get("headers");
        assertThat(headers).containsEntry("server", "Apache/2.4.41");
        assertThat(headers).containsEntry("x-powered-by", "PHP/8.1");
        assertThat(headers).containsEntry("x-content-type-options", "nosniff");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> cookies = (List<Map<String, Object>>) data.get("cookies");
        assertThat(cookies).hasSize(2);
        assertThat(cookies.get(0)).containsEntry("name", "SESSIONID")
                .containsEntry("secure", true)
                .containsEntry("httpOnly", true)
                .containsEntry("sameSite", "Strict");
        assertThat(cookies.get(1)).containsEntry("name", "tracker_id")
                .containsEntry("secure", false)
                .containsEntry("httpOnly", false)
                .containsEntry("sameSite", null);

        // Verify automated observation draft extraction
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).extracting(ObservationDraft::category)
                .contains("SECURITY_HEADERS", "INFO_DISCLOSURE", "COOKIE_SECURITY");

        // Missing HSTS, CSP, X-Frame-Options
        assertThat(observations).anyMatch(obs -> obs.category().equals("SECURITY_HEADERS")
                && obs.description().contains("Strict-Transport-Security")
                && obs.severityHeuristic() == SeverityHeuristic.MEDIUM);
        assertThat(observations).anyMatch(obs -> obs.category().equals("SECURITY_HEADERS")
                && obs.description().contains("Content-Security-Policy")
                && obs.severityHeuristic() == SeverityHeuristic.MEDIUM);
        assertThat(observations).anyMatch(obs -> obs.category().equals("SECURITY_HEADERS")
                && obs.description().contains("X-Frame-Options")
                && obs.severityHeuristic() == SeverityHeuristic.LOW);

        // Version banners in Server and X-Powered-By
        assertThat(observations).anyMatch(obs -> obs.category().equals("INFO_DISCLOSURE")
                && obs.description().contains("Apache/2.4.41")
                && obs.severityHeuristic() == SeverityHeuristic.LOW);
        assertThat(observations).anyMatch(obs -> obs.category().equals("INFO_DISCLOSURE")
                && obs.description().contains("PHP/8.1")
                && obs.severityHeuristic() == SeverityHeuristic.LOW);

        // Insecure tracker_id cookie (missing HttpOnly and SameSite)
        assertThat(observations).anyMatch(obs -> obs.category().equals("COOKIE_SECURITY")
                && obs.description().contains("tracker_id") && obs.description().contains("HttpOnly")
                && obs.severityHeuristic() == SeverityHeuristic.MEDIUM);
        assertThat(observations).anyMatch(obs -> obs.category().equals("COOKIE_SECURITY")
                && obs.description().contains("tracker_id") && obs.description().contains("SameSite")
                && obs.severityHeuristic() == SeverityHeuristic.LOW);
    }

    @Test
    @DisplayName("Follows safe redirect chain up to 3 hops when followRedirects is true")
    void followsRedirectChain() throws Exception {
        stubFor(get(urlEqualTo("/redirect-1"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "/redirect-2")));

        stubFor(get(urlEqualTo("/redirect-2"))
                .willReturn(aResponse()
                        .withStatus(301)
                        .withHeader("Location", "/redirect-final")));

        stubFor(get(urlEqualTo("/redirect-final"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody("Reached Final")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/redirect-1";
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("followRedirects", true),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.parsedData().get("statusCode")).isEqualTo(200);
        assertThat(outcome.parsedData().get("finalUrl")).isEqualTo("http://127.0.0.1:" + wireMockPort + "/redirect-final");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> chain = (List<Map<String, Object>>) outcome.parsedData().get("redirectChain");
        assertThat(chain).hasSize(2);
        assertThat(chain.get(0)).containsEntry("hop", 1).containsEntry("statusCode", 302);
        assertThat(chain.get(1)).containsEntry("hop", 2).containsEntry("statusCode", 301);

        assertThat(outcome.rawOutput()).contains("Redirect Hop 1").contains("Redirect Hop 2").contains("Final Response");
    }

    @Test
    @DisplayName("Blocks malicious redirect to prohibited IP (127.0.0.1 in PUBLIC mode) with PolicyViolationException")
    void blocksMaliciousRedirectInPublicMode() throws Exception {
        stubFor(get(urlEqualTo("/evil-redirect"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "http://127.0.0.1:" + wireMockPort + "/admin")));

        String targetUrl = "http://example.com/evil-redirect";
        ScopeAsset publicScope = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(false)
                .build();

        // Stubbed pinned IP for example.com
        Clock clock = Clock.systemUTC();
        PolicyEngine mockEngine = new PolicyEngine(new IpRangeValidator(), host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")}, clock);
        PinnedHttpClient mockClient = new PinnedHttpClient(mockEngine) {
            @Override
            public PinnedHttpResponse executeSingle(java.net.URI uri, InetAddress pinnedIp) {
                return new PinnedHttpResponse(
                        uri,
                        302,
                        "HTTP/1.1",
                        "Found",
                        Map.of("location", List.of("http://127.0.0.1/admin")),
                        List.of(),
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin",
                        new byte[0]
                );
            }
        };

        HttpHeadersTool publicTool = new HttpHeadersTool(mockClient, mockEngine);
        InetAddress publicIp = InetAddress.getByName("93.184.216.34");
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.PUBLIC,
                publicScope,
                Map.of("followRedirects", true),
                new com.ospysin.policy.PolicyDecision(true, "ok", "example.com", publicIp, SessionMode.PUBLIC, 0)
        );

        assertThatThrownBy(() -> publicTool.execute(context))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("Policy violation on redirect hop 1");
    }

    @Test
    @DisplayName("Blocks redirect chain that exceeds maximum 3 hops")
    void blocksExceededRedirectHops() {
        Clock clock = Clock.systemUTC();
        PolicyEngine localEngine = new PolicyEngine(new IpRangeValidator(), host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")}, clock);
        PinnedHttpClient loopingClient = new PinnedHttpClient(localEngine) {
            private int count = 0;
            @Override
            public PinnedHttpResponse executeSingle(java.net.URI uri, InetAddress pinnedIp) {
                count++;
                return new PinnedHttpResponse(
                        uri,
                        302,
                        "HTTP/1.1",
                        "Found",
                        Map.of("location", List.of("http://127.0.0.1:" + wireMockPort + "/loop-" + count)),
                        List.of(),
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/loop-" + count,
                        new byte[0]
                );
            }
        };

        HttpHeadersTool loopTool = new HttpHeadersTool(loopingClient, localEngine);
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://127.0.0.1:" + wireMockPort + "/loop-0",
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("followRedirects", true),
                null
        );

        assertThatThrownBy(() -> loopTool.execute(context))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("Redirect hop limit exceeded");
    }

    @Test
    @DisplayName("Handles gzip compressed 200 OK response")
    void gzipCompressedResponse() throws Exception {
        byte[] gzippedBody = gzip("Hello compressed body payload!");
        stubFor(get(urlEqualTo("/gzip-test"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withHeader("Content-Encoding", "gzip")
                        .withBody(gzippedBody)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/gzip-test";
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
        assertThat(outcome.parsedData().get("statusCode")).isEqualTo(200);
        assertThat(outcome.rawOutput()).contains("Content-Encoding: gzip");
    }

    @Test
    @DisplayName("Handles chunked gzip compressed 200 OK response")
    void chunkedGzipCompressedResponse() throws Exception {
        int testPort = findFreeAllowedPortExcluding(wireMockPort);
        byte[] gzipped = gzip("Hello chunked gzip data!");
        try (ServerSocket serverSocket = new ServerSocket()) {
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new InetSocketAddress("127.0.0.1", testPort));

            CompletableFuture<Void> serverTask = CompletableFuture.runAsync(() -> {
                try (Socket s = serverSocket.accept()) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
                    String line;
                    while ((line = reader.readLine()) != null && !line.isEmpty()) {
                        // consume request headers
                    }
                    OutputStream out = s.getOutputStream();
                    String responseHeaders = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/plain\r\n"
                            + "Transfer-Encoding: chunked\r\n"
                            + "Content-Encoding: gzip\r\n"
                            + "Connection: close\r\n\r\n";
                    out.write(responseHeaders.getBytes(StandardCharsets.US_ASCII));
                    out.write(Integer.toHexString(gzipped.length).getBytes(StandardCharsets.US_ASCII));
                    out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                    out.write(gzipped);
                    out.write("\r\n0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (Exception ignored) {
                }
            });

            ToolExecutionContext context = new ToolExecutionContext(
                    UUID.randomUUID(),
                    UUID.randomUUID(),
                    "http://127.0.0.1:" + testPort + "/chunked-gzip",
                    SessionMode.LOCAL,
                    localScopeAsset,
                    Map.of(),
                    null
            );

            ToolExecutionOutcome outcome = tool.execute(context);
            serverTask.join();

            assertThat(outcome.hasErrors()).isFalse();
            assertThat(outcome.parsedData().get("statusCode")).isEqualTo(200);
            assertThat(outcome.rawOutput()).contains("Transfer-Encoding: chunked");
        }
    }

    @Test
    @DisplayName("Handles 302 redirect with Content-Encoding: gzip and Content-Length: 0 without EOFException")
    void gzipRedirectWithZeroContentLength() throws Exception {
        stubFor(get(urlEqualTo("/redirect-gzip"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "/final-landing")
                        .withHeader("Content-Encoding", "gzip")
                        .withHeader("Content-Length", "0")));

        stubFor(get(urlEqualTo("/final-landing"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("OK")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/redirect-gzip";
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("followRedirects", true),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.parsedData().get("statusCode")).isEqualTo(200);
        assertThat(outcome.parsedData().get("finalUrl")).isEqualTo("http://127.0.0.1:" + wireMockPort + "/final-landing");
    }

    @Test
    @DisplayName("Reuses pre-resolved IP from context policy decision without triggering DNS resolution")
    void reusesPreResolvedIpWithoutDnsResolution() throws Exception {
        stubFor(get(urlEqualTo("/pinned-test"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("Pinned IP ok")));

        AtomicInteger dnsCallCount = new AtomicInteger(0);
        PolicyEngine countingEngine = new PolicyEngine(
                new IpRangeValidator(),
                host -> {
                    dnsCallCount.incrementAndGet();
                    return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
                },
                Clock.systemUTC()
        );

        PinnedHttpClient client = new PinnedHttpClient(countingEngine);
        HttpHeadersTool countingTool = new HttpHeadersTool(client, countingEngine);

        InetAddress preResolvedIp = InetAddress.getByName("127.0.0.1");
        com.ospysin.policy.PolicyDecision preDecision = new com.ospysin.policy.PolicyDecision(
                true,
                "Pre-approved",
                "127.0.0.1",
                preResolvedIp,
                SessionMode.LOCAL,
                0
        );

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://127.0.0.1:" + wireMockPort + "/pinned-test",
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPort", wireMockPort),
                preDecision
        );

        ToolExecutionOutcome outcome = countingTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.parsedData().get("statusCode")).isEqualTo(200);
        // DNS resolver must NOT have been called because pre-flight decision with resolvedIp was reused
        assertThat(dnsCallCount.get()).isEqualTo(0);
    }

    private static byte[] gzip(String text) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return baos.toByteArray();
    }

    private static int findFreeAllowedPort() {
        for (int port : List.of(8443, 3000, 5000, 8080, 8000)) {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress("127.0.0.1", port));
                return port;
            } catch (IOException ignored) {
            }
        }
        throw new IllegalStateException("No allowed test port free");
    }

    private static int findFreeAllowedPortExcluding(int excludedPort) {
        for (int port : List.of(8443, 3000, 5000, 8080, 8000)) {
            if (port == excludedPort) {
                continue;
            }
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress("127.0.0.1", port));
                return port;
            } catch (IOException ignored) {
            }
        }
        throw new IllegalStateException("No allowed test port free (excluding " + excludedPort + ")");
    }
}
