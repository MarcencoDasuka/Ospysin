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

class RobotsTxtToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static RobotsTxtTool tool;
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
        tool = new RobotsTxtTool(pinnedHttpClient, policyEngine);

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
    @DisplayName("Parses valid robots.txt, extracts user-agents, sitemaps, and flags sensitive paths")
    void parsesValidRobotsTxtAndDetectsSensitivePaths() throws Exception {
        String robotsContent = """
                # Robots.txt file
                User-agent: Googlebot
                Disallow: /admin/
                Disallow: /.env
                Allow: /admin/public/

                User-agent: *
                Disallow: /actuator/heapdump
                Disallow: /private/data
                Allow: /
                Sitemap: http://127.0.0.1:%d/sitemap.xml
                """.formatted(wireMockPort);

        stubFor(get(urlEqualTo("/robots.txt"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody(robotsContent)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/some/page";
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
        assertThat(outcome.rawOutput()).contains("User-agent: Googlebot");

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("found")).isEqualTo(true);
        assertThat(data.get("statusCode")).isEqualTo(200);

        @SuppressWarnings("unchecked")
        Map<String, Map<String, List<String>>> userAgents = (Map<String, Map<String, List<String>>>) data.get("userAgents");
        assertThat(userAgents).containsKey("Googlebot").containsKey("*");

        List<String> googleDisallows = userAgents.get("Googlebot").get("disallowed");
        assertThat(googleDisallows).contains("/admin/", "/.env");

        List<String> starDisallows = userAgents.get("*").get("disallowed");
        assertThat(starDisallows).contains("/actuator/heapdump", "/private/data");

        @SuppressWarnings("unchecked")
        List<String> sitemaps = (List<String>) data.get("sitemaps");
        assertThat(sitemaps).contains("http://127.0.0.1:" + wireMockPort + "/sitemap.xml");

        @SuppressWarnings("unchecked")
        List<String> sensitivePaths = (List<String>) data.get("sensitivePaths");
        assertThat(sensitivePaths).contains("/admin/", "/.env", "/actuator/heapdump", "/private/data");

        // Verify observations
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(2);

        assertThat(observations).anyMatch(obs -> obs.category().equals("RECON_ROBOTS")
                && obs.severityHeuristic() == SeverityHeuristic.MEDIUM
                && obs.description().contains("/admin/")
                && obs.description().contains("/.env"));

        assertThat(observations).anyMatch(obs -> obs.category().equals("RECON_ROBOTS")
                && obs.severityHeuristic() == SeverityHeuristic.INFO
                && obs.description().contains("1 sitemap(s)"));
    }

    @Test
    @DisplayName("Handles 404 Not Found response gracefully with found = false")
    void handles404NotFoundGracefully() throws Exception {
        stubFor(get(urlEqualTo("/robots.txt"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withBody("Not Found")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/";
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
        assertThat(data.get("found")).isEqualTo(false);
        assertThat(data.get("statusCode")).isEqualTo(404);

        @SuppressWarnings("unchecked")
        Map<String, Object> userAgents = (Map<String, Object>) data.get("userAgents");
        assertThat(userAgents).isEmpty();

        @SuppressWarnings("unchecked")
        List<String> sitemaps = (List<String>) data.get("sitemaps");
        assertThat(sitemaps).isEmpty();

        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("Handles HTML soft-404 gracefully with found = false")
    void handlesHtmlSoft404Gracefully() throws Exception {
        String soft404Html = "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Oops! Page Not Found</h1></body></html>";
        stubFor(get(urlEqualTo("/robots.txt"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/html")
                        .withBody(soft404Html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/";
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
        assertThat(data.get("found")).isEqualTo(false);
        assertThat(data.get("statusCode")).isEqualTo(200);

        @SuppressWarnings("unchecked")
        Map<String, Object> userAgents = (Map<String, Object>) data.get("userAgents");
        assertThat(userAgents).isEmpty();
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("P14-03 Regression: Distinguishes true sensitive endpoints from benign keyword prefixes in robots.txt")
    void differentiatesSensitivePathsFromBenignPrefixMatches() throws Exception {
        String robotsContent = """
                User-agent: *
                Disallow: /author/john-doe
                Disallow: /apiculture-tips
                Disallow: /configuration-guide
                Disallow: /dba-blog
                Disallow: /admin/users
                Disallow: /auth/login
                Disallow: /api/v1
                Disallow: /config/database.yml
                Disallow: /db/dump.sql
                """;

        stubFor(get(urlEqualTo("/robots.txt"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody(robotsContent)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/";
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
        List<String> sensitivePaths = (List<String>) data.get("sensitivePaths");

        // Must NOT match benign words sharing prefix
        assertThat(sensitivePaths).doesNotContain(
                "/author/john-doe",
                "/apiculture-tips",
                "/configuration-guide",
                "/dba-blog"
        );

        // MUST match genuine sensitive paths
        assertThat(sensitivePaths).contains(
                "/admin/users",
                "/auth/login",
                "/api/v1",
                "/config/database.yml",
                "/db/dump.sql"
        );

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        String obsDesc = observations.get(0).description();
        assertThat(obsDesc).contains("/admin/users", "/auth/login", "/api/v1");
        assertThat(obsDesc).doesNotContain("author", "apiculture", "configuration-guide", "dba-blog");
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
