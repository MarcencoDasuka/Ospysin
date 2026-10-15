package com.ospysin.tools.probes;

import com.github.tomakehurst.wiremock.WireMockServer;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlsInfoToolTest {

    private static WireMockServer wireMockTlsServer;
    private static int tlsPort;
    private static PolicyEngine policyEngine;
    private static TlsInfoTool tool;
    private static ScopeAsset localScopeAsset;
    private static Clock clock;

    @BeforeAll
    static void setUpAll() {
        tlsPort = findFreeAllowedPort();
        wireMockTlsServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
                .bindAddress("127.0.0.1")
                .httpDisabled(true)
                .httpsPort(tlsPort));
        wireMockTlsServer.start();

        clock = Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        IpRangeValidator ipRangeValidator = new IpRangeValidator();
        policyEngine = new PolicyEngine(ipRangeValidator, host -> new InetAddress[]{InetAddress.getByName(host)}, clock);

        tool = new TlsInfoTool(policyEngine, clock);

        localScopeAsset = ScopeAsset.builder()
                .assetType(AssetType.IP)
                .value("127.0.0.1")
                .isWildcard(false)
                .build();
    }

    @AfterAll
    static void tearDownAll() {
        if (wireMockTlsServer != null) {
            wireMockTlsServer.stop();
        }
    }

    @Test
    @DisplayName("validateParams rejects non-allowlisted port with 422 ValidationException")
    void validateParamsRejectsDisallowedPort() {
        assertThatThrownBy(() -> tool.validateParams(Map.of("port", 25)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).hasSize(1);
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("port");
                });

        assertThatThrownBy(() -> tool.validateParams(Map.of("port", 22)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("validateParams accepts allowlisted ports and null or empty params")
    void validateParamsAcceptsAllowedPorts() {
        tool.validateParams(Map.of("port", 443));
        tool.validateParams(Map.of("port", 8443));
        tool.validateParams(Map.of("port", 8080));
        tool.validateParams(Collections.emptyMap());
        tool.validateParams(null);
    }

    @Test
    @DisplayName("Inspects TLS handshake against local TLS server, extracting certificates, ciphers, and observations")
    void inspectsLiveTlsHandshake() throws Exception {
        String targetUrl = "https://127.0.0.1:" + tlsPort;
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("port", tlsPort),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);

        // Architectural invariant: score = null
        assertThat(outcome.score()).isNull();
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("protocol")).isNotNull();
        assertThat(data.get("cipherSuite")).isNotNull();
        assertThat(data.get("subject")).isNotNull().asString().contains("CN=");
        assertThat(data.get("issuer")).isNotNull();
        assertThat(data.get("serialNumber")).isNotNull();
        assertThat(data.get("notBefore")).isNotNull();
        assertThat(data.get("notAfter")).isNotNull();
        assertThat(data.get("daysUntilExpiry")).isNotNull();
        assertThat(data.get("selfSigned")).isEqualTo(true);

        // Verification of raw output formatting
        assertThat(outcome.rawOutput()).contains("TLS Connection Summary:")
                .contains("Peer Certificate:")
                .contains("Self-Signed:       true");

        // WireMock's certificate is self-signed, which produces a MEDIUM severity observation
        assertThat(outcome.observations()).anyMatch(obs -> obs.category().equals("TLS_CERTIFICATE")
                && obs.description().contains("self-signed")
                && obs.severityHeuristic() == SeverityHeuristic.MEDIUM);
    }

    @Test
    @DisplayName("Observation heuristics: calls real tool.extractObservations verifying all 6 heuristics and clean handshake")
    void observationHeuristicsCoverage() {
        // 1. Deprecated protocol (TLSv1, TLSv1.1, SSLv3) -> HIGH (TLS_PROTOCOL)
        List<ObservationDraft> tls1Obs = tool.extractObservations("TLSv1", "TLS_AES_256_GCM_SHA384", 90, false, true, "example.com");
        assertThat(tls1Obs).hasSize(1);
        assertThat(tls1Obs.get(0).category()).isEqualTo("TLS_PROTOCOL");
        assertThat(tls1Obs.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);
        assertThat(tls1Obs.get(0).description()).contains("TLSv1");

        List<ObservationDraft> ssl3Obs = tool.extractObservations("SSLv3", "TLS_AES_256_GCM_SHA384", 90, false, true, "example.com");
        assertThat(ssl3Obs).anyMatch(o -> o.category().equals("TLS_PROTOCOL") && o.description().contains("SSLv3"));

        List<ObservationDraft> tls11Obs = tool.extractObservations("TLSv1.1", "TLS_AES_256_GCM_SHA384", 90, false, true, "example.com");
        assertThat(tls11Obs).anyMatch(o -> o.category().equals("TLS_PROTOCOL") && o.description().contains("TLSv1.1"));

        // 2. Weak cipher suite (3DES, RC4) -> HIGH (TLS_CIPHER)
        List<ObservationDraft> weak3des = tool.extractObservations("TLSv1.3", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 90, false, true, "example.com");
        assertThat(weak3des).hasSize(1);
        assertThat(weak3des.get(0).category()).isEqualTo("TLS_CIPHER");
        assertThat(weak3des.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);
        assertThat(weak3des.get(0).description()).contains("3DES");

        List<ObservationDraft> weakRc4 = tool.extractObservations("TLSv1.3", "TLS_RSA_WITH_RC4_128_SHA", 90, false, true, "example.com");
        assertThat(weakRc4).anyMatch(o -> o.category().equals("TLS_CIPHER") && o.description().contains("RC4"));

        // 3. Expired certificate (daysUntilExpiry = -15) -> HIGH (TLS_CERTIFICATE)
        List<ObservationDraft> expired = tool.extractObservations("TLSv1.3", "TLS_AES_256_GCM_SHA384", -15, false, true, "example.com");
        assertThat(expired).hasSize(1);
        assertThat(expired.get(0).category()).isEqualTo("TLS_CERTIFICATE");
        assertThat(expired.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);
        assertThat(expired.get(0).description()).contains("expired 15 days ago");

        // 4. Expiring-soon certificate (0 <= daysUntilExpiry <= 30, e.g. 14) -> MEDIUM (TLS_CERTIFICATE)
        List<ObservationDraft> expiringSoon = tool.extractObservations("TLSv1.3", "TLS_AES_256_GCM_SHA384", 14, false, true, "example.com");
        assertThat(expiringSoon).hasSize(1);
        assertThat(expiringSoon.get(0).category()).isEqualTo("TLS_CERTIFICATE");
        assertThat(expiringSoon.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
        assertThat(expiringSoon.get(0).description()).contains("will expire in 14 days");

        // 5. Self-signed certificate (selfSigned = true) -> MEDIUM (TLS_CERTIFICATE)
        List<ObservationDraft> selfSigned = tool.extractObservations("TLSv1.3", "TLS_AES_256_GCM_SHA384", 90, true, true, "example.com");
        assertThat(selfSigned).hasSize(1);
        assertThat(selfSigned.get(0).category()).isEqualTo("TLS_CERTIFICATE");
        assertThat(selfSigned.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
        assertThat(selfSigned.get(0).description()).contains("self-signed");

        // 6. Hostname mismatch (hostnameVerified = false) -> HIGH (TLS_CERTIFICATE)
        List<ObservationDraft> mismatch = tool.extractObservations("TLSv1.3", "TLS_AES_256_GCM_SHA384", 90, false, false, "example.com");
        assertThat(mismatch).hasSize(1);
        assertThat(mismatch.get(0).category()).isEqualTo("TLS_CERTIFICATE");
        assertThat(mismatch.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);
        assertThat(mismatch.get(0).description()).contains("hostname mismatch");

        // 7. Clean modern handshake -> 0 observations
        List<ObservationDraft> clean = tool.extractObservations("TLSv1.3", "TLS_AES_256_GCM_SHA384", 90, false, true, "example.com");
        assertThat(clean).isEmpty();
    }

    @Test
    @DisplayName("P10-03: Reuses context.policyDecision() resolvedIp without triggering redundant DNS lookup")
    void reusesPreResolvedIpWithoutDnsResolution() throws Exception {
        java.util.concurrent.atomic.AtomicInteger dnsResolutionCount = new java.util.concurrent.atomic.AtomicInteger(0);
        com.ospysin.policy.DnsResolver trackingResolver = host -> {
            dnsResolutionCount.incrementAndGet();
            return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
        };

        PolicyEngine countingEngine = new PolicyEngine(new IpRangeValidator(), trackingResolver, clock);
        TlsInfoTool countingTool = new TlsInfoTool(countingEngine, clock);

        com.ospysin.policy.PolicyDecision preResolvedDecision = new com.ospysin.policy.PolicyDecision(
                true,
                "Pre-resolved test decision",
                "127.0.0.1",
                InetAddress.getByName("127.0.0.1"),
                SessionMode.LOCAL,
                clock.millis()
        );

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "https://127.0.0.1:" + tlsPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("port", tlsPort),
                preResolvedDecision
        );

        ToolExecutionOutcome outcome = countingTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        // Must NOT have invoked DNS resolver because context.policyDecision() was already supplied!
        assertThat(dnsResolutionCount.get()).isZero();
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
}
