package com.ospysin.policy;

import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import com.ospysin.shared.error.PolicyViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class PolicyEngineTest {

    private static final Instant FROZEN_TIME = Instant.parse("2026-10-14T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(FROZEN_TIME, ZoneOffset.UTC);

    private IpRangeValidator ipRangeValidator;
    private DnsResolver dnsResolver;
    private AuditEventRepository auditEventRepository;
    private PolicyEngine policyEngine;

    @BeforeEach
    void setUp() throws UnknownHostException {
        ipRangeValidator = new IpRangeValidator();
        dnsResolver = mock(DnsResolver.class);
        auditEventRepository = mock(AuditEventRepository.class);

        // Default mock DNS: example.com -> 93.184.216.34 (public)
        when(dnsResolver.resolveAll("example.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("93.184.216.34")});

        policyEngine = new PolicyEngine(ipRangeValidator, dnsResolver, auditEventRepository, CLOCK);
    }

    @Test
    @DisplayName("Allowed HTTP and HTTPS URLs on public hosts pass evaluation in PUBLIC mode")
    void allowedHttpAndHttpsUrls() {
        PolicyDecision decision = policyEngine.evaluate("https://example.com/api/test", SessionMode.PUBLIC, null);

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.targetHost()).isEqualTo("example.com");
        assertThat(decision.resolvedIp().getHostAddress()).isEqualTo("93.184.216.34");
        assertThat(decision.mode()).isEqualTo(SessionMode.PUBLIC);
        assertThat(decision.evaluationTimestamp()).isEqualTo(FROZEN_TIME.toEpochMilli());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "file:///etc/passwd",
            "gopher://127.0.0.1:70/",
            "ftp://example.com/test",
            "ldap://example.com:389/dc=example",
            "dict://example.com:2628/",
            "data:text/plain;base64,SGVsbG8="
    })
    @DisplayName("Prohibited URL schemes are rejected")
    void prohibitedSchemes(String url) {
        PolicyDecision decision = policyEngine.evaluate(url, SessionMode.PUBLIC, null);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).containsIgnoringCase("Prohibited URL scheme");
    }

    @ParameterizedTest
    @ValueSource(ints = {80, 443, 8000, 8080, 8443, 3000, 5000})
    @DisplayName("Allowed web ports pass evaluation")
    void allowedWebPorts(int port) {
        PolicyDecision decision = policyEngine.evaluate("http://example.com:" + port + "/status", SessionMode.PUBLIC, null);
        assertThat(decision.allowed()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(ints = {22, 21, 25, 3306, 5432, 6379, 27017})
    @DisplayName("Prohibited non-web ports are rejected")
    void prohibitedPorts(int port) {
        PolicyDecision decision = policyEngine.evaluate("http://example.com:" + port + "/data", SessionMode.PUBLIC, null);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).containsIgnoringCase("Prohibited port: " + port);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://user:pass@example.com/path",
            "http://admin@example.com:8080/dashboard"
    })
    @DisplayName("URLs with embedded userinfo credentials are rejected")
    void embeddedCredentialsRejected(String url) {
        PolicyDecision decision = policyEngine.evaluate(url, SessionMode.PUBLIC, null);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).containsIgnoringCase("Embedded userinfo");
    }

    @Test
    @DisplayName("DNS resolution with multiple IPs where 1 of 2 is private MUST reject entire evaluation in PUBLIC mode")
    void multiIpResponseRejectsIfAnyProhibited() throws UnknownHostException {
        when(dnsResolver.resolveAll("dual.example.com")).thenReturn(new InetAddress[]{
                InetAddress.getByName("93.184.216.34"), // public
                InetAddress.getByName("10.0.0.1")       // private RFC 1918
        });

        PolicyDecision decision = policyEngine.evaluate("https://dual.example.com", SessionMode.PUBLIC, null);

        assertThat(decision.allowed())
                .as("Multi-IP containing 10.0.0.1 must be rejected in PUBLIC mode")
                .isFalse();
        assertThat(decision.reason()).containsIgnoringCase("Prohibited in PUBLIC mode");
    }

    @Test
    @DisplayName("Multi-IP containing cloud metadata is rejected in BOTH LOCAL and PUBLIC modes")
    void multiIpWithMetadataRejectedInBothModes() throws UnknownHostException {
        when(dnsResolver.resolveAll("meta.example.com")).thenReturn(new InetAddress[]{
                InetAddress.getByName("93.184.216.34"),
                InetAddress.getByName("169.254.169.254")
        });

        PolicyDecision publicDecision = policyEngine.evaluate("http://meta.example.com", SessionMode.PUBLIC, null);
        assertThat(publicDecision.allowed()).isFalse();

        PolicyDecision localDecision = policyEngine.evaluate("http://meta.example.com", SessionMode.LOCAL, null);
        assertThat(localDecision.allowed()).isFalse();
    }

    @Test
    @DisplayName("Obfuscated IP literals (octal, hex, dword, dotted-hex, short) and trailing FQDN dots")
    void obfuscatedIpLiterals() {
        // Octal 0177.0.0.1 = 127.0.0.1
        PolicyDecision octalDecision = policyEngine.evaluate("http://0177.0.0.1:8080", SessionMode.PUBLIC, null);
        assertThat(octalDecision.allowed()).isFalse();
        assertThat(octalDecision.resolvedIp().getHostAddress()).isEqualTo("127.0.0.1");

        // Hex 0x7f000001 = 127.0.0.1
        PolicyDecision hexDecision = policyEngine.evaluate("http://0x7f000001", SessionMode.PUBLIC, null);
        assertThat(hexDecision.allowed()).isFalse();
        assertThat(hexDecision.resolvedIp().getHostAddress()).isEqualTo("127.0.0.1");

        // Dotted-hex 0x7f.0.0.1:8080 = 127.0.0.1:8080 (URI.getHost() is null)
        PolicyDecision dottedHexDecision = policyEngine.evaluate("http://0x7f.0.0.1:8080", SessionMode.PUBLIC, null);
        assertThat(dottedHexDecision.allowed()).isFalse();
        assertThat(dottedHexDecision.resolvedIp().getHostAddress()).isEqualTo("127.0.0.1");

        // Decimal integer 2130706433 = 127.0.0.1
        PolicyDecision dwordDecision = policyEngine.evaluate("http://2130706433", SessionMode.PUBLIC, null);
        assertThat(dwordDecision.allowed()).isFalse();
        assertThat(dwordDecision.resolvedIp().getHostAddress()).isEqualTo("127.0.0.1");

        // Short 2-part IP 127.1 = 127.0.0.1 (URI.getHost() is null)
        PolicyDecision shortIpDecision = policyEngine.evaluate("http://127.1", SessionMode.PUBLIC, null);
        assertThat(shortIpDecision.allowed()).isFalse();
        assertThat(shortIpDecision.resolvedIp().getHostAddress()).isEqualTo("127.0.0.1");

        // Trailing FQDN root dot: example.com. stripped and evaluated
        PolicyDecision trailingDotHost = policyEngine.evaluate("https://example.com./api", SessionMode.PUBLIC, null);
        assertThat(trailingDotHost.allowed()).isTrue();
        assertThat(trailingDotHost.targetHost()).isEqualTo("example.com");

        // Trailing IP root dot: 127.0.0.1. stripped and evaluated as loopback
        PolicyDecision trailingDotIp = policyEngine.evaluate("http://127.0.0.1./", SessionMode.PUBLIC, null);
        assertThat(trailingDotIp.allowed()).isFalse();
        assertThat(trailingDotIp.resolvedIp().getHostAddress()).isEqualTo("127.0.0.1");
    }

    @Test
    @DisplayName("Scope containment: exact match and wildcard matching")
    void scopeContainment() throws UnknownHostException {
        when(dnsResolver.resolveAll("api.example.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("93.184.216.35")});
        when(dnsResolver.resolveAll("other.org"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("93.184.216.36")});

        // Exact scope asset
        ScopeAsset exactScope = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(false)
                .build();

        PolicyDecision allowedExact = policyEngine.evaluate("https://example.com", SessionMode.PUBLIC, exactScope);
        assertThat(allowedExact.allowed()).isTrue();

        PolicyDecision rejectedSubdomainOnExact = policyEngine.evaluate("https://api.example.com", SessionMode.PUBLIC, exactScope);
        assertThat(rejectedSubdomainOnExact.allowed()).isFalse();
        assertThat(rejectedSubdomainOnExact.reason()).containsIgnoringCase("outside authorized scope");

        // Wildcard scope asset
        ScopeAsset wildcardScope = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(true)
                .build();

        PolicyDecision allowedSubdomainOnWildcard = policyEngine.evaluate("https://api.example.com", SessionMode.PUBLIC, wildcardScope);
        assertThat(allowedSubdomainOnWildcard.allowed()).isTrue();

        PolicyDecision outsideScope = policyEngine.evaluate("https://other.org", SessionMode.PUBLIC, wildcardScope);
        assertThat(outsideScope.allowed()).isFalse();
    }

    @Test
    @DisplayName("Subdomain takeover rule permits subdomains of target host and external CNAME destinations")
    void subdomainTakeoverRule() throws UnknownHostException {
        when(dnsResolver.resolveAll("sub.example.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("93.184.216.37")});
        when(dnsResolver.resolveAll("mybucket.s3.amazonaws.com"))
                .thenReturn(new InetAddress[]{InetAddress.getByName("52.216.1.1")});

        ScopeAsset scope = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(false)
                .build();

        // Standard evaluation: sub.example.com rejected because isWildcard=false
        PolicyDecision standardDecision = policyEngine.evaluate("https://sub.example.com", SessionMode.PUBLIC, scope, false);
        assertThat(standardDecision.allowed()).isFalse();

        // Subdomain takeover evaluation: sub.example.com permitted
        PolicyDecision takeoverDecision = policyEngine.evaluate("https://sub.example.com", SessionMode.PUBLIC, scope, true);
        assertThat(takeoverDecision.allowed()).isTrue();

        // CNAME fingerprinting to external cloud endpoint permitted through scope check, undergoes IP validation
        PolicyDecision cnameDecision = policyEngine.evaluate("https://mybucket.s3.amazonaws.com", SessionMode.PUBLIC, scope, true);
        assertThat(cnameDecision.allowed()).isTrue();

        // Unrelated external domain MUST still be rejected even when isSubdomainTakeoverCheck is true
        PolicyDecision unrelatedDecision = policyEngine.evaluate("https://unrelated-evil.org", SessionMode.PUBLIC, scope, true);
        assertThat(unrelatedDecision.allowed()).isFalse();
        assertThat(unrelatedDecision.reason()).containsIgnoringCase("outside authorized scope");
    }

    @Test
    @DisplayName("Redirect revalidation enforces 3-hop cap, scheme rules, and destination IP validation")
    void redirectRevalidation() throws UnknownHostException {
        URI initialUri = URI.create("https://example.com/step1");

        // Hop 1 relative redirect
        PolicyDecision hop1 = policyEngine.evaluateRedirectHop(initialUri, "/step2", 1, SessionMode.PUBLIC, null);
        assertThat(hop1.allowed()).isTrue();

        // Hop 3 allowed
        PolicyDecision hop3 = policyEngine.evaluateRedirectHop(initialUri, "https://example.com/step4", 3, SessionMode.PUBLIC, null);
        assertThat(hop3.allowed()).isTrue();

        // Hop 4 rejected (cap is 3)
        PolicyDecision hop4 = policyEngine.evaluateRedirectHop(initialUri, "https://example.com/step5", 4, SessionMode.PUBLIC, null);
        assertThat(hop4.allowed()).isFalse();
        assertThat(hop4.reason()).containsIgnoringCase("hop limit exceeded");

        // Redirect to private RFC 1918 in PUBLIC mode rejected
        PolicyDecision privateRedirect = policyEngine.evaluateRedirectHop(initialUri, "http://10.0.0.1/admin", 1, SessionMode.PUBLIC, null);
        assertThat(privateRedirect.allowed()).isFalse();
        assertThat(privateRedirect.reason()).containsIgnoringCase("Prohibited in PUBLIC mode");

        // Redirect to cloud metadata rejected
        PolicyDecision metadataRedirect = policyEngine.evaluateRedirectHop(initialUri, "http://169.254.169.254/latest", 1, SessionMode.LOCAL, null);
        assertThat(metadataRedirect.allowed()).isFalse();
        assertThat(metadataRedirect.reason()).containsIgnoringCase("Prohibited IP range");
    }

    @Test
    @DisplayName("DNS Rebinding Harness: PinnedDnsResolver keeps socket pinned strictly to initial verified IP")
    void dnsRebindingHarness() throws UnknownHostException {
        // Simulate a malicious DNS resolver that flips from public to loopback
        AtomicInteger lookupCount = new AtomicInteger(0);
        DnsResolver maliciousResolver = host -> {
            int count = lookupCount.incrementAndGet();
            if (count == 1) {
                // First lookup during policy pre-flight: legitimate public IP
                return new InetAddress[]{InetAddress.getByName("93.184.216.34")};
            } else {
                // Subsequent lookup during socket connection: loopback 127.0.0.1
                return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
            }
        };

        PolicyEngine rebindingEngine = new PolicyEngine(ipRangeValidator, maliciousResolver, auditEventRepository, CLOCK);

        // Pre-flight policy evaluation
        PolicyDecision decision = rebindingEngine.evaluate("http://rebinding-victim.com", SessionMode.PUBLIC, null);
        assertThat(decision.allowed()).isTrue();
        assertThat(decision.resolvedIp().getHostAddress()).isEqualTo("93.184.216.34");

        // Create PinnedDnsResolver with approved IP
        PinnedDnsResolver pinnedResolver = new PinnedDnsResolver("rebinding-victim.com", decision.resolvedIp());

        // Subsequent lookup via pinned resolver returns the pinned public IP, NOT the flipped 127.0.0.1
        InetAddress[] socketAddresses = pinnedResolver.resolveAll("rebinding-victim.com");
        assertThat(socketAddresses).hasSize(1);
        assertThat(socketAddresses[0].getHostAddress())
                .as("Pinned resolver must keep the connection strictly on 93.184.216.34")
                .isEqualTo("93.184.216.34");

        // Verify unpinned resolver would have flipped
        InetAddress[] unpinnedAddresses = maliciousResolver.resolveAll("rebinding-victim.com");
        assertThat(unpinnedAddresses[0].getHostAddress())
                .as("Unpinned resolver flips to 127.0.0.1")
                .isEqualTo("127.0.0.1");

        // Querying an unexpected host with PinnedDnsResolver throws UnknownHostException
        assertThatThrownBy(() -> pinnedResolver.resolveAll("different-host.com"))
                .isInstanceOf(UnknownHostException.class);
    }

    @Test
    @DisplayName("Forensic audit event is recorded with POLICY_EVALUATED type and complete metadata")
    void recordAuditLogging() {
        AuditSession session = mock(AuditSession.class);
        PolicyDecision decision = policyEngine.evaluate("https://example.com/api", SessionMode.PUBLIC, null);

        when(auditEventRepository.save(any(AuditEvent.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AuditEvent event = policyEngine.recordAudit(session, decision);

        assertThat(event).isNotNull();
        assertThat(event.getEventType()).isEqualTo(AuditEventType.POLICY_EVALUATED);
        assertThat(event.getPayload()).containsEntry("allowed", true);
        assertThat(event.getPayload()).containsEntry("targetHost", "example.com");
        assertThat(event.getPayload()).containsEntry("resolvedIp", "93.184.216.34");
        assertThat(event.getPayload()).containsEntry("mode", "PUBLIC");
        assertThat(event.getTimestamp()).isEqualTo(FROZEN_TIME);

        verify(auditEventRepository).save(any(AuditEvent.class));
    }

    @Test
    @DisplayName("enforce() returns PolicyDecision when allowed and throws PolicyViolationException when rejected")
    void enforceMethod() {
        // Allowed: returns decision
        PolicyDecision allowed = policyEngine.enforce("https://example.com", SessionMode.PUBLIC, null);
        assertThat(allowed.allowed()).isTrue();

        // Prohibited: throws PolicyViolationException with invalidParams populated
        assertThatThrownBy(() -> policyEngine.enforce("http://127.0.0.1", SessionMode.PUBLIC, null))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("Policy violation")
                .satisfies(ex -> {
                    PolicyViolationException pve = (PolicyViolationException) ex;
                    assertThat(pve.getInvalidParams()).hasSize(1);
                    assertThat(pve.getInvalidParams().get(0).name()).isEqualTo("targetUrl");
                    assertThat(pve.getInvalidParams().get(0).reason()).containsIgnoringCase("Loopback");
                });
    }

    @Test
    @DisplayName("Unknown host during DNS resolution returns rejected decision")
    void unknownHostResolution() throws UnknownHostException {
        when(dnsResolver.resolveAll("nonexistent.invalid"))
                .thenThrow(new UnknownHostException("Host not found"));

        PolicyDecision decision = policyEngine.evaluate("https://nonexistent.invalid", SessionMode.PUBLIC, null);
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).containsIgnoringCase("Unable to resolve");
    }

    @Test
    @DisplayName("evaluate() handles bracketed IPv6 URL with port against unbracketed IPv6 ScopeAsset")
    void evaluateBracketedIpv6UrlWithPortAgainstUnbracketedScopeAsset() {
        ScopeAsset ipv6ScopeAsset = ScopeAsset.builder()
                .assetType(AssetType.IP)
                .value("2606:2800:220:1:248:1893:25c8:1946")
                .isWildcard(false)
                .build();

        PolicyDecision decision = policyEngine.evaluate(
                "http://[2606:2800:220:1:248:1893:25c8:1946]:8080/api",
                SessionMode.PUBLIC,
                ipv6ScopeAsset
        );

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.targetHost()).isEqualTo("2606:2800:220:1:248:1893:25c8:1946");
        assertThat(decision.resolvedIp()).isNotNull();
        assertThat(decision.resolvedIp().getHostAddress()).isEqualTo("2606:2800:220:1:248:1893:25c8:1946");
    }

    @Test
    @DisplayName("evaluate() rejects target hosts exceeding RFC 1035 maximum length of 253 characters")
    void evaluateRejectsOversizedHostLength() {
        String oversizedHost = "a".repeat(60) + "." + "b".repeat(60) + "." + "c".repeat(60) + "." + "d".repeat(60) + "." + "e".repeat(20) + ".com";
        assertThat(oversizedHost.length()).isGreaterThan(253);

        PolicyDecision decision = policyEngine.evaluate("https://" + oversizedHost + "/api", SessionMode.PUBLIC, null);
        assertThat(decision.allowed()).isFalse();
        assertThat(decision.reason()).containsIgnoringCase("exceeds maximum DNS length of 253 characters");
    }
}
