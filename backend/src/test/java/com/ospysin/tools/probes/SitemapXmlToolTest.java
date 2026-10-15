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

class SitemapXmlToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static SitemapXmlTool tool;
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
        tool = new SitemapXmlTool(pinnedHttpClient, policyEngine);

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
    @DisplayName("validateParams rejects invalid customPath and maxUrls")
    void validateParamsRejectsInvalid() {
        // Path traversal
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPath", "/../etc/passwd")))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> assertThat(((ValidationException) ex).getInvalidParams())
                        .extracting(ip -> ip.name()).contains("customPath"));

        // Protocol-relative
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPath", "//evil.com/sitemap.xml")))
                .isInstanceOf(ValidationException.class);

        // Absolute URL
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPath", "http://evil.com/sitemap.xml")))
                .isInstanceOf(ValidationException.class);

        // Does not start with slash
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPath", "sitemap.xml")))
                .isInstanceOf(ValidationException.class);

        // Backslash traversal
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPath", "/..\\secret")))
                .isInstanceOf(ValidationException.class);

        // CR / LF injection
        assertThatThrownBy(() -> tool.validateParams(Map.of("customPath", "/sitemap.xml\r\nHeader: value")))
                .isInstanceOf(ValidationException.class);

        // maxUrls out of range
        assertThatThrownBy(() -> tool.validateParams(Map.of("maxUrls", 0)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxUrls", 1001)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxUrls", -10)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Collections.singletonMap("customPath", null)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Collections.singletonMap("maxUrls", null)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("maxUrls", 50.5)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams accepts valid customPath and maxUrls")
    void validateParamsAcceptsValid() {
        tool.validateParams(Map.of("customPath", "/sitemap.xml", "maxUrls", 500));
        tool.validateParams(Map.of("customPath", "/sitemaps/sitemap_index.xml", "maxUrls", 1000));
        tool.validateParams(Map.of("maxUrls", 1));
        tool.validateParams(Collections.emptyMap());
        tool.validateParams(null);
    }

    @Test
    @DisplayName("Parses valid <urlset> XML, extracts URLs, and flags sensitive endpoints")
    void parsesValidUrlsetAndExtractsSensitiveEndpoints() throws Exception {
        String xmlContent = """
                <?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                  <url>
                    <loc>http://127.0.0.1:%d/</loc>
                  </url>
                  <url>
                    <loc>http://127.0.0.1:%d/admin/dashboard</loc>
                  </url>
                  <url>
                    <loc>http://127.0.0.1:%d/api/v1/users</loc>
                  </url>
                  <url>
                    <loc>http://127.0.0.1:%d/about-us</loc>
                  </url>
                </urlset>
                """.formatted(wireMockPort, wireMockPort, wireMockPort, wireMockPort);

        stubFor(get(urlEqualTo("/sitemap.xml"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(xmlContent)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPath", "/sitemap.xml", "maxUrls", 100),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("found")).isEqualTo(true);
        assertThat(data.get("statusCode")).isEqualTo(200);
        assertThat(data.get("urlCount")).isEqualTo(4);

        @SuppressWarnings("unchecked")
        List<String> sampleUrls = (List<String>) data.get("sampleUrls");
        assertThat(sampleUrls).hasSize(4)
                .contains("http://127.0.0.1:" + wireMockPort + "/admin/dashboard",
                          "http://127.0.0.1:" + wireMockPort + "/api/v1/users");

        @SuppressWarnings("unchecked")
        List<String> sensitivePaths = (List<String>) data.get("sensitivePathsFound");
        assertThat(sensitivePaths).contains(
                "http://127.0.0.1:" + wireMockPort + "/admin/dashboard",
                "http://127.0.0.1:" + wireMockPort + "/api/v1/users"
        );

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("RECON_SITEMAP");
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.LOW);
        assertThat(observations.get(0).description()).contains("/admin/dashboard");
    }

    @Test
    @DisplayName("Parses <sitemapindex> XML and extracts sitemap index references")
    void parsesSitemapIndexXml() throws Exception {
        String xmlContent = """
                <?xml version="1.0" encoding="UTF-8"?>
                <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                  <sitemap>
                    <loc>http://127.0.0.1:%d/sitemap-posts.xml</loc>
                  </sitemap>
                  <sitemap>
                    <loc>http://127.0.0.1:%d/sitemap-products.xml</loc>
                  </sitemap>
                </sitemapindex>
                """.formatted(wireMockPort, wireMockPort);

        stubFor(get(urlEqualTo("/sitemap_index.xml"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(xmlContent)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPath", "/sitemap_index.xml"),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("found")).isEqualTo(true);

        @SuppressWarnings("unchecked")
        List<String> indexUrls = (List<String>) data.get("sitemapIndexUrls");
        assertThat(indexUrls).contains(
                "http://127.0.0.1:" + wireMockPort + "/sitemap-posts.xml",
                "http://127.0.0.1:" + wireMockPort + "/sitemap-products.xml"
        );
    }

    @Test
    @DisplayName("XXE Falsification: Malicious XML with DOCTYPE entity is rejected safely without entity resolution")
    void rejectsXxeInjectionAttemptSafely() throws Exception {
        String xxePayload = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE foo [
                  <!ELEMENT foo ANY >
                  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
                ]>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                  <url>
                    <loc>&xxe;</loc>
                  </url>
                </urlset>
                """;

        stubFor(get(urlEqualTo("/xxe-sitemap.xml"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(xxePayload)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPath", "/xxe-sitemap.xml"),
                null
        );

        // Parser must reject DOCTYPE and prevent XXE disclosure cleanly without throwing unhandled error
        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("found")).isEqualTo(false);
        assertThat(data.get("urlCount")).isEqualTo(0);

        @SuppressWarnings("unchecked")
        List<String> sampleUrls = (List<String>) data.get("sampleUrls");
        assertThat(sampleUrls).isEmpty();
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("P14-02 Regression: Preserves query string in customPath resolution without percent-encoding question mark")
    void preservesQueryStringInCustomPathResolution() throws Exception {
        String xmlContent = """
                <?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                  <url>
                    <loc>http://127.0.0.1:%d/post-1</loc>
                  </url>
                </urlset>
                """.formatted(wireMockPort);

        stubFor(get(urlEqualTo("/sitemap.xml?type=posts&page=1"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(xmlContent)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPath", "/sitemap.xml?type=posts&page=1"),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("found")).isEqualTo(true);
        assertThat(data.get("urlCount")).isEqualTo(1);

        verify(getRequestedFor(urlEqualTo("/sitemap.xml?type=posts&page=1")));
    }

    @Test
    @DisplayName("P14-03 Regression: Distinguishes true sensitive endpoints from benign keyword prefixes in sitemap.xml")
    void differentiatesSensitiveSitemapUrlsFromBenignPrefixMatches() throws Exception {
        String xmlContent = """
                <?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                  <url><loc>http://127.0.0.1:%d/author/jane-doe</loc></url>
                  <url><loc>http://127.0.0.1:%d/apiculture-guide</loc></url>
                  <url><loc>http://127.0.0.1:%d/configuration-faq</loc></url>
                  <url><loc>http://127.0.0.1:%d/admin/dashboard</loc></url>
                  <url><loc>http://127.0.0.1:%d/auth/jwt</loc></url>
                </urlset>
                """.formatted(wireMockPort, wireMockPort, wireMockPort, wireMockPort, wireMockPort);

        stubFor(get(urlEqualTo("/sitemap-prefixes.xml"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/xml")
                        .withBody(xmlContent)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("customPath", "/sitemap-prefixes.xml"),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();

        @SuppressWarnings("unchecked")
        List<String> sensitivePaths = (List<String>) data.get("sensitivePathsFound");

        assertThat(sensitivePaths).doesNotContain(
                "http://127.0.0.1:" + wireMockPort + "/author/jane-doe",
                "http://127.0.0.1:" + wireMockPort + "/apiculture-guide",
                "http://127.0.0.1:" + wireMockPort + "/configuration-faq"
        );

        assertThat(sensitivePaths).contains(
                "http://127.0.0.1:" + wireMockPort + "/admin/dashboard",
                "http://127.0.0.1:" + wireMockPort + "/auth/jwt"
        );

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        String obsDesc = observations.get(0).description();
        assertThat(obsDesc).contains("/admin/dashboard", "/auth/jwt");
        assertThat(obsDesc).doesNotContain("author", "apiculture", "configuration-faq");
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
