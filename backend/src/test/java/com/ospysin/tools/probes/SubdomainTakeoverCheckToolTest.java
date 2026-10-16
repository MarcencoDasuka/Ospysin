package com.ospysin.tools.probes;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.HostRateLimiter;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import com.ospysin.tools.recon.DnsLookupClient;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class SubdomainTakeoverCheckToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static PinnedHttpClient pinnedHttpClient;
    private static DnsLookupClient dnsLookupClient;
    private static ToolExecutionRepository toolExecutionRepo;
    private static ToolResultRepository toolResultRepo;
    private static HostRateLimiter hostRateLimiter;
    private static SubdomainTakeoverCheckTool tool;
    private static ScopeAsset localScopeAsset;

    @BeforeAll
    static void setUpAll() {
        wireMockPort = findFreeAllowedPort();
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(wireMockPort));
        wireMockServer.start();
        WireMock.configureFor("127.0.0.1", wireMockPort);

        Clock clock = Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        IpRangeValidator ipRangeValidator = new IpRangeValidator();
        policyEngine = new PolicyEngine(ipRangeValidator, host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")}, clock);

        pinnedHttpClient = new PinnedHttpClient(policyEngine);
        dnsLookupClient = Mockito.mock(DnsLookupClient.class);
        toolExecutionRepo = Mockito.mock(ToolExecutionRepository.class);
        toolResultRepo = Mockito.mock(ToolResultRepository.class);
        hostRateLimiter = Mockito.mock(HostRateLimiter.class);

        tool = new SubdomainTakeoverCheckTool(dnsLookupClient, pinnedHttpClient, policyEngine, toolExecutionRepo, toolResultRepo, hostRateLimiter);

        localScopeAsset = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(true)
                .build();
    }

    @AfterAll
    static void tearDownAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @BeforeEach
    void resetAll() {
        wireMockServer.resetAll();
        Mockito.reset(dnsLookupClient, toolExecutionRepo, toolResultRepo, hostRateLimiter);
    }

    @Test
    @DisplayName("validateParams rejects invalid subdomains (scheme, path, port, invalid chars, >25 items)")
    void validateParamsRejectsInvalidSubdomains() {
        // Scheme in subdomain
        assertThatThrownBy(() -> tool.validateParams(Map.of("subdomains", List.of("http://sub.example.com"))))
                .isInstanceOf(ValidationException.class);

        // Path in subdomain
        assertThatThrownBy(() -> tool.validateParams(Map.of("subdomains", List.of("sub.example.com/api"))))
                .isInstanceOf(ValidationException.class);

        // Port in subdomain
        assertThatThrownBy(() -> tool.validateParams(Map.of("subdomains", List.of("sub.example.com:8080"))))
                .isInstanceOf(ValidationException.class);

        // Invalid characters
        assertThatThrownBy(() -> tool.validateParams(Map.of("subdomains", List.of("sub!example.com"))))
                .isInstanceOf(ValidationException.class);

        // More than 25 subdomains
        List<String> tooMany = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            tooMany.add("sub" + i + ".example.com");
        }
        assertThatThrownBy(() -> tool.validateParams(Map.of("subdomains", tooMany)))
                .isInstanceOf(ValidationException.class);

        // Null subdomains
        Map<String, Object> nullSubdomains = new HashMap<>();
        nullSubdomains.put("subdomains", null);
        assertThatThrownBy(() -> tool.validateParams(nullSubdomains))
                .isInstanceOf(ValidationException.class);

        // Valid subdomains accepted
        tool.validateParams(Map.of("subdomains", List.of("sub1.example.com", "sub2.example.com")));
        tool.validateParams(Collections.emptyMap());
    }

    @Test
    @DisplayName("Scope enforcement: rejects user-supplied subdomain outside target host scope")
    void rejectsOutOfScopeSubdomain() {
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://example.com",
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("subdomains", List.of("attacker.com")),
                null
        );

        assertThatThrownBy(() -> tool.execute(context))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("outside authorized scope");
    }

    @Test
    @DisplayName("Vulnerable CNAME takeover detection on GitHub Pages (fingerprint: 'There isn't a GitHub Pages site here')")
    void detectsGitHubPagesTakeover() throws Exception {
        when(dnsLookupClient.queryRecords("docs.example.com", "CNAME"))
                .thenReturn(List.of("example.github.io."));

        stubFor(get(urlEqualTo("/"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withBody("404 Not Found - There isn't a GitHub Pages site here")));

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://example.com:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("subdomains", List.of("docs.example.com")),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.score()).isNull();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(true);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> records = (List<Map<String, Object>>) data.get("cnameRecordsChecked");
        assertThat(records).hasSize(1);
        Map<String, Object> record = records.get(0);
        assertThat(record.get("domain")).isEqualTo("docs.example.com");
        assertThat(record.get("cnameTarget")).isEqualTo("example.github.io");
        assertThat(record.get("provider")).isEqualTo("GitHub Pages");
        assertThat(record.get("status")).isEqualTo("VULNERABLE");
        assertThat(record.get("fingerprintDetected")).isEqualTo("There isn't a GitHub Pages site here");

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("SUBDOMAIN_TAKEOVER");
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);

        Mockito.verify(hostRateLimiter, Mockito.atLeastOnce()).acquire(Mockito.anyString());
    }

    @Test
    @DisplayName("Vulnerable CNAME takeover detection on AWS S3 (fingerprint: 'NoSuchBucket')")
    void detectsAwsS3Takeover() throws Exception {
        when(dnsLookupClient.queryRecords("assets.example.com", "CNAME"))
                .thenReturn(List.of("mybucket.s3.amazonaws.com."));

        stubFor(get(urlEqualTo("/"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withBody("<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>")));

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://example.com:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("subdomains", List.of("assets.example.com")),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(true);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> records = (List<Map<String, Object>>) data.get("cnameRecordsChecked");
        assertThat(records.get(0).get("status")).isEqualTo("VULNERABLE");
        assertThat(records.get(0).get("provider")).isEqualTo("AWS S3");
    }

    @Test
    @DisplayName("Secure CNAME: Destination responds normally without error fingerprints -> status = SECURE")
    void secureCnameRespondsNormally() throws Exception {
        when(dnsLookupClient.queryRecords("app.example.com", "CNAME"))
                .thenReturn(List.of("myapp.herokuapp.com."));

        stubFor(get(urlEqualTo("/"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("Welcome to our active application homepage")));

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://example.com:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("subdomains", List.of("app.example.com")),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(false);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> records = (List<Map<String, Object>>) data.get("cnameRecordsChecked");
        assertThat(records.get(0).get("status")).isEqualTo("SECURE");
        assertThat(records.get(0).get("fingerprintDetected")).isNull();
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("Auto-harvests subdomains from session tls_info and extract_links steps")
    void autoHarvestsSubdomainsFromSessionSteps() throws Exception {
        UUID sessionId = UUID.randomUUID();
        UUID tlsExecId = UUID.randomUUID();
        UUID linksExecId = UUID.randomUUID();

        ToolExecution tlsExec = ToolExecution.builder()
                .session(null)
                .toolId("tls_info")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .leaseEpoch(1)
                .attempts(1)
                .build();
        var idField = ToolExecution.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(tlsExec, tlsExecId);

        ToolExecution linksExec = ToolExecution.builder()
                .session(null)
                .toolId("extract_links")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .leaseEpoch(1)
                .attempts(1)
                .build();
        idField.set(linksExec, linksExecId);

        when(toolExecutionRepo.findBySessionIdOrderByCreatedAtAsc(sessionId))
                .thenReturn(List.of(tlsExec, linksExec));

        ToolResult tlsResult = ToolResult.builder()
                .execution(tlsExec)
                .rawOutput("dummy")
                .parsedData(Map.of("sanEntries", List.of("example.com", "*.sub1.example.com", "otherdomain.com")))
                .build();
        when(toolResultRepo.findByExecutionId(tlsExecId))
                .thenReturn(Optional.of(tlsResult));

        ToolResult linksResult = ToolResult.builder()
                .execution(linksExec)
                .rawOutput("dummy")
                .parsedData(Map.of("internalLinks", List.of("http://sub2.example.com/login", "http://ignored.org")))
                .build();
        when(toolResultRepo.findByExecutionId(linksExecId))
                .thenReturn(Optional.of(linksResult));

        when(dnsLookupClient.queryRecords(anyString(), eq("CNAME")))
                .thenReturn(Collections.emptyList());

        ToolExecutionContext context = new ToolExecutionContext(
                sessionId,
                UUID.randomUUID(),
                "http://example.com",
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of(),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        // Verify DNS lookup was invoked for harvested in-scope subdomains (example.com, sub1.example.com, sub2.example.com)
        // and NOT for otherdomain.com or ignored.org
        Mockito.verify(dnsLookupClient).queryRecords("example.com", "CNAME");
        Mockito.verify(dnsLookupClient).queryRecords("sub1.example.com", "CNAME");
        Mockito.verify(dnsLookupClient).queryRecords("sub2.example.com", "CNAME");
        Mockito.verify(dnsLookupClient, Mockito.never()).queryRecords("otherdomain.com", "CNAME");
        Mockito.verify(dnsLookupClient, Mockito.never()).queryRecords("ignored.org", "CNAME");
    }

    @Test
    @DisplayName("Dangling NXDOMAIN CNAME is flagged with DANGLING_NXDOMAIN status and MEDIUM observation")
    void danglingNxdomainFlagged() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        IpRangeValidator ipRangeValidator = new IpRangeValidator();
        // PolicyEngine with unresolvable host resolver
        PolicyEngine nxPolicyEngine = new PolicyEngine(ipRangeValidator, host -> {
            throw new java.net.UnknownHostException("Host not found");
        }, clock);

        SubdomainTakeoverCheckTool nxTool = new SubdomainTakeoverCheckTool(
                dnsLookupClient, pinnedHttpClient, nxPolicyEngine, toolExecutionRepo, toolResultRepo
        );

        when(dnsLookupClient.queryRecords("dangling.example.com", "CNAME"))
                .thenReturn(List.of("unclaimed.github.io."));

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://example.com",
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("subdomains", List.of("dangling.example.com")),
                null
        );

        ToolExecutionOutcome outcome = nxTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(true);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> records = (List<Map<String, Object>>) data.get("cnameRecordsChecked");
        assertThat(records.get(0).get("status")).isEqualTo("DANGLING_NXDOMAIN");
        assertThat(records.get(0).get("fingerprintDetected")).isEqualTo("NXDOMAIN");

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("SUBDOMAIN_TAKEOVER");
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
    }

    @Test
    @DisplayName("PolicyEngine blocks CNAME resolving to private IP in PUBLIC mode -> status = POLICY_BLOCKED")
    void policyBlockedWhenCnameResolvesToPrivateIpInPublicMode() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        IpRangeValidator ipRangeValidator = new IpRangeValidator();
        // Resolves to private 10.0.0.1
        PolicyEngine publicPolicyEngine = new PolicyEngine(ipRangeValidator, host -> new InetAddress[]{InetAddress.getByName("10.0.0.1")}, clock);
        SubdomainTakeoverCheckTool publicTool = new SubdomainTakeoverCheckTool(
                dnsLookupClient, pinnedHttpClient, publicPolicyEngine, toolExecutionRepo, toolResultRepo, hostRateLimiter
        );

        when(dnsLookupClient.queryRecords("internal.example.com", "CNAME"))
                .thenReturn(List.of("private-bucket.s3.amazonaws.com."));

        ScopeAsset publicScope = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(true)
                .build();

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://example.com",
                SessionMode.PUBLIC,
                publicScope,
                Map.of("subdomains", List.of("internal.example.com")),
                null
        );

        ToolExecutionOutcome outcome = publicTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(false);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> records = (List<Map<String, Object>>) data.get("cnameRecordsChecked");
        assertThat(records).hasSize(1);
        assertThat(records.get(0).get("status")).isEqualTo("POLICY_BLOCKED");
        assertThat(outcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("extractHost correctly parses bracketed IPv6 literals with port")
    void extractHostHandlesBracketedIpv6() throws Exception {
        ScopeAsset ipv6Scope = ScopeAsset.builder()
                .assetType(AssetType.IP)
                .value("2001:db8::1")
                .isWildcard(false)
                .build();

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://[2001:db8::1]:8080/path",
                SessionMode.LOCAL,
                ipv6Scope,
                Map.of("subdomains", List.of("2001:db8::1")),
                null
        );

        when(dnsLookupClient.queryRecords("2001:db8::1", "CNAME"))
                .thenReturn(Collections.emptyList());

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("isVulnerable")).isEqualTo(false);
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
