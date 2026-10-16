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

class CorsMisconfigCheckToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static HostRateLimiter hostRateLimiter;
    private static CorsMisconfigCheckTool tool;
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
        tool = new CorsMisconfigCheckTool(pinnedHttpClient, policyEngine, hostRateLimiter);

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
    @DisplayName("validateParams rejects invalid customOrigins (paths, invalid schemes, CRLF, >10 items)")
    void validateParamsRejectsInvalidOrigins() {
        // Null customOrigins
        Map<String, Object> nullOrigins = new HashMap<>();
        nullOrigins.put("customOrigins", null);
        assertThatThrownBy(() -> tool.validateParams(nullOrigins))
                .isInstanceOf(ValidationException.class);

        // Path in origin
        assertThatThrownBy(() -> tool.validateParams(Map.of("customOrigins", List.of("https://example.com/api"))))
                .isInstanceOf(ValidationException.class);

        // Invalid scheme (ftp)
        assertThatThrownBy(() -> tool.validateParams(Map.of("customOrigins", List.of("ftp://example.com"))))
                .isInstanceOf(ValidationException.class);

        // CRLF in origin
        assertThatThrownBy(() -> tool.validateParams(Map.of("customOrigins", List.of("https://example.com\r\n"))))
                .isInstanceOf(ValidationException.class);

        // More than 10 origins
        List<String> tooMany = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            tooMany.add("https://domain" + i + ".com");
        }
        assertThatThrownBy(() -> tool.validateParams(Map.of("customOrigins", tooMany)))
                .isInstanceOf(ValidationException.class);

        // Valid custom origins accepted
        tool.validateParams(Map.of("customOrigins", List.of("null", "https://trusted.example.com", "http://sub.example.com:8080")));
        tool.validateParams(Collections.emptyMap());
    }

    @Test
    @DisplayName("Arbitrary origin reflection + Access-Control-Allow-Credentials: true -> ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS")
    void detectsArbitraryOriginReflectionWithCredentials() throws Exception {
        stubFor(get(urlEqualTo("/"))
                .atPriority(10)
                .willReturn(aResponse().withStatus(200).withBody("Default OK")));

        stubFor(get(urlEqualTo("/"))
                .atPriority(1)
                .withHeader("Origin", equalTo("https://attacker.com"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Access-Control-Allow-Origin", "https://attacker.com")
                        .withHeader("Access-Control-Allow-Credentials", "true")
                        .withBody("OK")));

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
        assertThat(outcome.score()).isNull();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(true);
        assertThat(data.get("vulnerabilityType")).isEqualTo("ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS");
        assertThat(data.get("severity")).isEqualTo("HIGH");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> probes = (List<Map<String, Object>>) data.get("probes");
        assertThat(probes).anyMatch(p -> "https://attacker.com".equals(p.get("testedOrigin"))
                && "https://attacker.com".equals(p.get("reflectedOrigin"))
                && Boolean.TRUE.equals(p.get("allowCredentials"))
                && Boolean.TRUE.equals(p.get("exploitable")));

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("CORS_MISCONFIG");
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);

        Mockito.verify(hostRateLimiter, Mockito.atLeastOnce()).acquire(Mockito.anyString());
    }

    @Test
    @DisplayName("Null origin reflection + Access-Control-Allow-Credentials: true -> NULL_ORIGIN_ALLOWED_WITH_CREDENTIALS")
    void detectsNullOriginWithCredentials() throws Exception {
        stubFor(get(urlEqualTo("/"))
                .atPriority(10)
                .willReturn(aResponse().withStatus(200).withBody("Default OK")));

        stubFor(get(urlEqualTo("/"))
                .atPriority(1)
                .withHeader("Origin", equalTo("null"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Access-Control-Allow-Origin", "null")
                        .withHeader("Access-Control-Allow-Credentials", "true")
                        .withBody("OK")));

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
        assertThat(data.get("isVulnerable")).isEqualTo(true);
        assertThat(data.get("vulnerabilityType")).isEqualTo("NULL_ORIGIN_ALLOWED_WITH_CREDENTIALS");
        assertThat(data.get("severity")).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("Prefix/suffix bypass detection -> TRUST_BOUNDARY_BYPASS_WITH_CREDENTIALS")
    void detectsTrustBoundaryBypass() throws Exception {
        String bypassOrigin = "http://127.0.0.1.attacker.com";
        stubFor(get(urlEqualTo("/"))
                .atPriority(10)
                .willReturn(aResponse().withStatus(200).withBody("Default OK")));

        stubFor(get(urlEqualTo("/"))
                .atPriority(1)
                .withHeader("Origin", equalTo(bypassOrigin))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Access-Control-Allow-Origin", bypassOrigin)
                        .withHeader("Access-Control-Allow-Credentials", "true")
                        .withBody("OK")));

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
        assertThat(data.get("isVulnerable")).isEqualTo(true);
        assertThat(data.get("vulnerabilityType")).isEqualTo("TRUST_BOUNDARY_BYPASS_WITH_CREDENTIALS");
        assertThat(data.get("severity")).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("Safe CORS configuration: server does not reflect untrusted origins -> isVulnerable = false")
    void safeCorsConfiguration() throws Exception {
        stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("Safe Response with No CORS headers")));

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
        assertThat(data.get("isVulnerable")).isEqualTo(false);
        assertThat(data.get("vulnerabilityType")).isEqualTo("NONE");
        assertThat(data.get("severity")).isEqualTo("INFO");
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("IPv6 targetHost skips prefix and suffix bypass origin concatenation")
    void skipsPrefixSuffixProbesForIpv6TargetHost() throws Exception {
        stubFor(get(anyUrl())
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("Safe Response")));

        ScopeAsset ipv6Scope = ScopeAsset.builder()
                .assetType(AssetType.IP)
                .value("::1")
                .isWildcard(false)
                .build();

        String targetUrl = "http://[::1]:" + wireMockPort + "/";
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                ipv6Scope,
                Map.of(),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> probes = (List<Map<String, Object>>) data.get("probes");
        assertThat(probes).noneMatch(p -> ((String) p.get("testedOrigin")).contains(".attacker.com"));
        assertThat(probes).noneMatch(p -> ((String) p.get("testedOrigin")).contains("evil-"));
        assertThat(probes).extracting(p -> (String) p.get("testedOrigin"))
                .containsExactlyInAnyOrder("https://attacker.com", "null");
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
