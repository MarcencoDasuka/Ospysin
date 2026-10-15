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
import com.ospysin.shared.error.PolicyViolationException;
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

class TechDetectToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static TechDetectTool tool;
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
        tool = new TechDetectTool(pinnedHttpClient, policyEngine);

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
    @DisplayName("Detects Apache HTTP Server and PHP from response headers and cookies with version disclosure")
    void detectsApacheAndPhpFromHeadersAndCookies() throws Exception {
        stubFor(get(urlEqualTo("/apache-php"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1")
                        .withHeader("X-Powered-By", "PHP/8.1.2")
                        .withHeader("Set-Cookie", "PHPSESSID=abc123456789; path=/")
                        .withBody("<html><body><h1>Hello World</h1></body></html>")));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/apache-php";
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

        // Verification of architectural invariants
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("statusCode")).isEqualTo(200);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> techs = (List<Map<String, Object>>) data.get("technologies");
        assertThat(techs).isNotEmpty();

        // Check Apache detection
        Optional<Map<String, Object>> apacheOpt = techs.stream()
                .filter(t -> "Apache HTTP Server".equals(t.get("name")))
                .findFirst();
        assertThat(apacheOpt).isPresent();
        assertThat(apacheOpt.get().get("version")).isEqualTo("2.4.49");
        assertThat(apacheOpt.get().get("category")).isEqualTo("Web Server");
        assertThat(apacheOpt.get().get("confidence")).isEqualTo("CONFIRMED");

        // Check PHP detection
        Optional<Map<String, Object>> phpOpt = techs.stream()
                .filter(t -> "PHP".equals(t.get("name")))
                .findFirst();
        assertThat(phpOpt).isPresent();
        assertThat(phpOpt.get().get("version")).isEqualTo("8.1.2");
        assertThat(phpOpt.get().get("category")).isEqualTo("Backend Runtime");
        assertThat(phpOpt.get().get("confidence")).isEqualTo("CONFIRMED");

        // Check observations: TECH_VERSION_EXPOSED and TECH_FINGERPRINT
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).anyMatch(o -> "TECH_VERSION_EXPOSED".equals(o.category())
                && o.description().contains("Apache HTTP Server 2.4.49")
                && o.severityHeuristic() == SeverityHeuristic.LOW);
        assertThat(observations).anyMatch(o -> "TECH_VERSION_EXPOSED".equals(o.category())
                && o.description().contains("PHP 8.1.2")
                && o.severityHeuristic() == SeverityHeuristic.LOW);
        assertThat(observations).anyMatch(o -> "TECH_FINGERPRINT".equals(o.category())
                && o.severityHeuristic() == SeverityHeuristic.INFO);
    }

    @Test
    @DisplayName("Detects WordPress, jQuery, Bootstrap, and Vue.js from DOM, meta generator, and script links")
    void detectsWpAndFrontendLibrariesFromDom() throws Exception {
        String html = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta name="generator" content="WordPress 6.2" />
                    <link rel="stylesheet" href="/wp-content/themes/theme/css/bootstrap-4.1.3.min.css" />
                    <script src="/wp-includes/js/jquery/jquery-3.4.1.min.js"></script>
                </head>
                <body>
                    <div id="app" data-v-abc1234>
                        <p>Welcome</p>
                    </div>
                </body>
                </html>
                """;

        stubFor(get(urlEqualTo("/cms-page"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Server", "nginx/1.24.0")
                        .withHeader("Set-Cookie", "wp-settings-1=something; path=/")
                        .withBody(html)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/cms-page";
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

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> techs = (List<Map<String, Object>>) outcome.parsedData().get("technologies");

        // Verify WordPress detected with version 6.2
        Optional<Map<String, Object>> wpOpt = techs.stream().filter(t -> "WordPress".equals(t.get("name"))).findFirst();
        assertThat(wpOpt).isPresent();
        assertThat(wpOpt.get().get("version")).isEqualTo("6.2");
        assertThat(wpOpt.get().get("category")).isEqualTo("CMS");
        assertThat(wpOpt.get().get("confidence")).isEqualTo("CONFIRMED");

        // Verify jQuery detected with version 3.4.1
        Optional<Map<String, Object>> jqOpt = techs.stream().filter(t -> "jQuery".equals(t.get("name"))).findFirst();
        assertThat(jqOpt).isPresent();
        assertThat(jqOpt.get().get("version")).isEqualTo("3.4.1");
        assertThat(jqOpt.get().get("category")).isEqualTo("Frontend Library");

        // Verify Bootstrap detected with version 4.1.3
        Optional<Map<String, Object>> bsOpt = techs.stream().filter(t -> "Bootstrap".equals(t.get("name"))).findFirst();
        assertThat(bsOpt).isPresent();
        assertThat(bsOpt.get().get("version")).isEqualTo("4.1.3");
        assertThat(bsOpt.get().get("category")).isEqualTo("Frontend Library");

        // Verify Vue.js detected via data-v- attribute
        Optional<Map<String, Object>> vueOpt = techs.stream().filter(t -> "Vue.js".equals(t.get("name"))).findFirst();
        assertThat(vueOpt).isPresent();
        assertThat(vueOpt.get().get("category")).isEqualTo("Frontend Framework");

        // Verify Nginx
        Optional<Map<String, Object>> nginxOpt = techs.stream().filter(t -> "Nginx".equals(t.get("name"))).findFirst();
        assertThat(nginxOpt).isPresent();
        assertThat(nginxOpt.get().get("version")).isEqualTo("1.24.0");
    }

    @Test
    @DisplayName("Detects Spring Boot from Whitelabel Error Page and Java JSESSIONID cookie")
    void detectsSpringBootAndJava() throws Exception {
        String springErrorPage = """
                <html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>
                """;

        stubFor(get(urlEqualTo("/spring-error"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Set-Cookie", "JSESSIONID=node01xyz789; Path=/; HttpOnly")
                        .withBody(springErrorPage)));

        String targetUrl = "http://127.0.0.1:" + wireMockPort + "/spring-error";
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

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> techs = (List<Map<String, Object>>) outcome.parsedData().get("technologies");

        assertThat(techs).anyMatch(t -> "Spring Boot".equals(t.get("name")) && "Backend Framework".equals(t.get("category")));
        assertThat(techs).anyMatch(t -> "Java / Servlet".equals(t.get("name")) && "Backend Runtime".equals(t.get("category")));
    }

    @Test
    @DisplayName("Policy violation in PUBLIC mode throws PolicyViolationException")
    void policyViolationThrowsException() {
        String privateTargetUrl = "http://192.168.1.100/test";
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                privateTargetUrl,
                SessionMode.PUBLIC,
                ScopeAsset.builder().assetType(AssetType.FQDN).value("example.com").build(),
                Map.of(),
                null
        );

        assertThatThrownBy(() -> tool.execute(context))
                .isInstanceOf(PolicyViolationException.class);
    }

    private static int findFreeAllowedPort() {
        for (int port : List.of(8080, 8000, 8443, 3000, 5000)) {
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
