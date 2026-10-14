package com.ospysin.policy;

import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.audit.AuditEvent;
import com.ospysin.shared.audit.AuditEventRepository;
import com.ospysin.shared.audit.AuditEventType;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Clock;
import java.util.*;

@Service
public class PolicyEngine {

    public static final int MAX_REDIRECT_HOPS = 3;
    public static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    public static final Set<Integer> ALLOWED_PORTS = Set.of(80, 443, 8000, 8080, 8443, 3000, 5000);
    private static final List<String> CNAME_TAKEOVER_PROVIDER_SUFFIXES = List.of(
            ".s3.amazonaws.com",
            ".amazonaws.com",
            ".github.io",
            ".herokuapp.com",
            ".vercel.app",
            ".azurewebsites.net",
            ".cloudfront.net",
            ".fastly.net"
    );

    private final IpRangeValidator ipRangeValidator;
    private final DnsResolver dnsResolver;
    private final AuditEventRepository auditEventRepository;
    private final Clock clock;

    @Autowired
    public PolicyEngine(IpRangeValidator ipRangeValidator,
                        DnsResolver dnsResolver,
                        @Autowired(required = false) AuditEventRepository auditEventRepository,
                        Clock clock) {
        this.ipRangeValidator = Objects.requireNonNull(ipRangeValidator, "ipRangeValidator must not be null");
        this.dnsResolver = Objects.requireNonNull(dnsResolver, "dnsResolver must not be null");
        this.auditEventRepository = auditEventRepository;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public PolicyEngine(IpRangeValidator ipRangeValidator,
                        DnsResolver dnsResolver,
                        Clock clock) {
        this(ipRangeValidator, dnsResolver, null, clock);
    }

    public PolicyDecision evaluate(String targetUrl, SessionMode mode, ScopeAsset scopeAsset) {
        return evaluate(targetUrl, mode, scopeAsset, false);
    }

    public PolicyDecision evaluate(String targetUrl, SessionMode mode, ScopeAsset scopeAsset, boolean isSubdomainTakeoverCheck) {
        long timestamp = clock.millis();

        if (targetUrl == null || targetUrl.isBlank()) {
            return new PolicyDecision(false, "Target URL must not be blank", null, null, mode, timestamp);
        }
        if (mode == null) {
            return new PolicyDecision(false, "Session mode must not be null", null, null, null, timestamp);
        }

        URI uri;
        try {
            uri = URI.create(targetUrl.trim());
        } catch (IllegalArgumentException e) {
            return new PolicyDecision(false, "Malformed target URL: " + e.getMessage(), null, null, mode, timestamp);
        }

        return evaluateUri(uri, mode, scopeAsset, isSubdomainTakeoverCheck, timestamp);
    }

    public PolicyDecision evaluate(URI uri, SessionMode mode, ScopeAsset scopeAsset) {
        return evaluateUri(uri, mode, scopeAsset, false, clock.millis());
    }

    private PolicyDecision evaluateUri(URI uri, SessionMode mode, ScopeAsset scopeAsset,
                                      boolean isSubdomainTakeoverCheck, long timestamp) {
        // 1. Scheme Allowlist
        String scheme = uri.getScheme();
        if (scheme == null) {
            return new PolicyDecision(false, "Missing URL scheme. Only 'http' and 'https' are permitted", null, null, mode, timestamp);
        }
        if (!ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            return new PolicyDecision(false, "Prohibited URL scheme: '" + scheme + "'. Only 'http' and 'https' are permitted", null, null, mode, timestamp);
        }

        // 2. Embedded Userinfo Credentials Check
        if (uri.getUserInfo() != null || (uri.getRawAuthority() != null && uri.getRawAuthority().contains("@"))) {
            return new PolicyDecision(false, "Embedded userinfo credentials are not permitted in target URLs", null, null, mode, timestamp);
        }

        // 3 & 4. Host & Port Extraction (handles dotted-hex/short IPv4 literals where URI.getHost() is null)
        String host = uri.getHost();
        int port = uri.getPort();

        if ((host == null || host.isBlank()) && uri.getRawAuthority() != null) {
            String authority = uri.getRawAuthority();
            int atIndex = authority.indexOf('@');
            if (atIndex >= 0) {
                authority = authority.substring(atIndex + 1);
            }
            int colonIndex = authority.lastIndexOf(':');
            if (colonIndex >= 0 && (!authority.contains("]") || colonIndex > authority.lastIndexOf(']'))) {
                try {
                    port = Integer.parseInt(authority.substring(colonIndex + 1));
                } catch (NumberFormatException e) {
                    return new PolicyDecision(false, "Invalid port in target URL authority", null, null, mode, timestamp);
                }
                host = authority.substring(0, colonIndex);
            } else {
                host = authority;
            }
        }

        if (port != -1 && !ALLOWED_PORTS.contains(port)) {
            return new PolicyDecision(false, "Prohibited port: " + port + ". Allowed web ports are 80, 443, 8000, 8080, 8443, 3000, 5000", null, null, mode, timestamp);
        }

        if (host == null || host.isBlank()) {
            return new PolicyDecision(false, "Target URL does not specify a valid host", null, null, mode, timestamp);
        }

        // Strip trailing FQDN root dots (e.g. "example.com." -> "example.com", "127.0.0.1." -> "127.0.0.1")
        while (host.endsWith(".") && host.length() > 1) {
            host = host.substring(0, host.length() - 1);
        }

        // 5. Scope Containment Check
        if (scopeAsset != null && !isWithinScope(host, scopeAsset, isSubdomainTakeoverCheck)) {
            return new PolicyDecision(false, "Target host '" + host + "' is outside authorized scope ('" + scopeAsset.getValue() + "')", host, null, mode, timestamp);
        }

        // 6. Obfuscated IP Literals Check
        InetAddress literalIp = ObfuscatedIpParser.parse(host);
        if (literalIp != null) {
            Optional<String> ipDenial = ipRangeValidator.validate(literalIp, mode);
            if (ipDenial.isPresent()) {
                return new PolicyDecision(false, ipDenial.get(), host, literalIp, mode, timestamp);
            }
            return new PolicyDecision(true, "Target IP is authorized under " + mode + " mode", host, literalIp, mode, timestamp);
        }

        // 7. DNS Pre-Flight & Multi-Record Validation
        InetAddress[] resolvedAddresses;
        try {
            resolvedAddresses = dnsResolver.resolveAll(host);
        } catch (UnknownHostException e) {
            return new PolicyDecision(false, "Unable to resolve target host: " + host, host, null, mode, timestamp);
        }

        if (resolvedAddresses == null || resolvedAddresses.length == 0) {
            return new PolicyDecision(false, "No DNS records found for host: " + host, host, null, mode, timestamp);
        }

        for (InetAddress address : resolvedAddresses) {
            Optional<String> ipDenial = ipRangeValidator.validate(address, mode);
            if (ipDenial.isPresent()) {
                return new PolicyDecision(false, ipDenial.get(), host, address, mode, timestamp);
            }
        }

        InetAddress pinnedAddress = resolvedAddresses[0];
        return new PolicyDecision(true, "Target host and IP are authorized under " + mode + " mode", host, pinnedAddress, mode, timestamp);
    }

    public PolicyDecision evaluateRedirectHop(URI currentUri, String locationHeader, int hopNumber,
                                              SessionMode mode, ScopeAsset scopeAsset) {
        long timestamp = clock.millis();
        if (hopNumber > MAX_REDIRECT_HOPS) {
            return new PolicyDecision(false, "Redirect hop limit exceeded (maximum " + MAX_REDIRECT_HOPS + " hops allowed)",
                    currentUri != null ? currentUri.getHost() : null, null, mode, timestamp);
        }
        if (locationHeader == null || locationHeader.isBlank()) {
            return new PolicyDecision(false, "Empty redirect location header",
                    currentUri != null ? currentUri.getHost() : null, null, mode, timestamp);
        }

        URI targetUri;
        try {
            if (currentUri != null) {
                targetUri = currentUri.resolve(locationHeader.trim());
            } else {
                targetUri = URI.create(locationHeader.trim());
            }
        } catch (IllegalArgumentException e) {
            return new PolicyDecision(false, "Invalid redirect URI: " + locationHeader,
                    null, null, mode, timestamp);
        }

        return evaluateUri(targetUri, mode, scopeAsset, false, timestamp);
    }

    public PolicyDecision enforce(String targetUrl, SessionMode mode, ScopeAsset scopeAsset) throws PolicyViolationException {
        PolicyDecision decision = evaluate(targetUrl, mode, scopeAsset);
        if (!decision.allowed()) {
            throw new PolicyViolationException(
                    "Policy violation: " + decision.reason(),
                    List.of(new InvalidParam("targetUrl", decision.reason()))
            );
        }
        return decision;
    }

    public AuditEvent recordAudit(AuditSession session, PolicyDecision decision) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("allowed", decision.allowed());
        payload.put("reason", decision.reason());
        payload.put("targetHost", decision.targetHost());
        payload.put("resolvedIp", decision.resolvedIp() != null ? decision.resolvedIp().getHostAddress() : null);
        payload.put("mode", decision.mode() != null ? decision.mode().name() : null);
        payload.put("evaluationTimestamp", decision.evaluationTimestamp());

        AuditEvent event = AuditEvent.builder()
                .session(session)
                .eventType(AuditEventType.POLICY_EVALUATED)
                .payload(payload)
                .timestamp(clock.instant())
                .build();

        if (auditEventRepository != null) {
            return auditEventRepository.save(event);
        }
        return event;
    }

    private boolean isWithinScope(String targetHost, ScopeAsset scopeAsset, boolean isSubdomainTakeoverCheck) {
        String rawScopeValue = scopeAsset.getValue();
        if (rawScopeValue == null || rawScopeValue.isBlank()) {
            return false;
        }

        String normalizedTarget = targetHost.toLowerCase(Locale.ROOT).trim();
        String scopeHost = extractHost(rawScopeValue).toLowerCase(Locale.ROOT).trim();

        // Exact match
        if (normalizedTarget.equalsIgnoreCase(scopeHost)) {
            return true;
        }

        // Wildcard match
        if (scopeAsset.isWildcard() || scopeHost.startsWith("*.")) {
            String domainSuffix = scopeHost.startsWith("*.") ? scopeHost.substring(2) : scopeHost;
            if (normalizedTarget.equalsIgnoreCase(domainSuffix) || normalizedTarget.endsWith("." + domainSuffix)) {
                return true;
            }
        }

        // Subdomain takeover check: subdomains of target host (*.<target_host>) or canonical CNAME targets are permitted
        if (isSubdomainTakeoverCheck) {
            if (normalizedTarget.endsWith("." + scopeHost) || normalizedTarget.equalsIgnoreCase(scopeHost)) {
                return true;
            }
            for (String suffix : CNAME_TAKEOVER_PROVIDER_SUFFIXES) {
                if (normalizedTarget.endsWith(suffix) || normalizedTarget.equalsIgnoreCase(suffix.substring(1))) {
                    return true;
                }
            }
            return false;
        }

        return false;
    }

    private String extractHost(String value) {
        String trimmed = value.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                URI uri = URI.create(trimmed);
                String host = uri.getHost();
                if (host != null) {
                    return host;
                }
            } catch (Exception ignored) {
            }
        }
        int slash = trimmed.indexOf('/');
        if (slash > 0) {
            trimmed = trimmed.substring(0, slash);
        }
        int colon = trimmed.indexOf(':');
        if (colon > 0 && !trimmed.contains("]")) {
            trimmed = trimmed.substring(0, colon);
        }
        return trimmed;
    }
}
