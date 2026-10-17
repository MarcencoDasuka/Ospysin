package com.ospysin.tools.probes;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Tool #4: HTTP response headers, cookies, security posture, and server banners direct probe.
 */
@Component
public class HttpHeadersTool implements OspysinTool {

    public static final String TOOL_ID = "http_headers";
    public static final long WIRE_CAP_BYTES = 1024 * 1024L; // 1 MB
    public static final long DECOMPRESSED_CAP_BYTES = 5 * 1024 * 1024L; // 5 MB
    public static final int READ_TIMEOUT_MS = 10_000; // 10s
    private static final Pattern VERSION_PATTERN = Pattern.compile(".*(/|\\s)\\d+(\\.\\d+)*.*|.*\\b\\d+\\.\\d+.*");

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;

    @Autowired
    public HttpHeadersTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        if (params == null) {
            return;
        }

        if (params.containsKey("customPort") && params.get("customPort") != null) {
            int port = parsePort(params.get("customPort"));
            if (!PolicyEngine.ALLOWED_PORTS.contains(port)) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("customPort", "customPort must be one of allowed ports: " + PolicyEngine.ALLOWED_PORTS))
                );
            }
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        URI initialUri = URI.create(context.targetUrl().trim());
        InetAddress pinnedIp;

        // Custom port override if specified
        if (context.inputParams().containsKey("customPort") && context.inputParams().get("customPort") != null) {
            int customPort = parsePort(context.inputParams().get("customPort"));
            if (!PolicyEngine.ALLOWED_PORTS.contains(customPort)) {
                throw new PolicyViolationException(
                        "Policy violation for customPort " + customPort + ": disallowed port",
                        List.of(new InvalidParam("customPort", "customPort must be one of allowed ports: " + PolicyEngine.ALLOWED_PORTS))
                );
            }
            initialUri = new URI(
                    initialUri.getScheme(),
                    initialUri.getUserInfo(),
                    initialUri.getHost(),
                    customPort,
                    initialUri.getPath(),
                    initialUri.getQuery(),
                    initialUri.getFragment()
            );

            if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
                // Reuse pre-flight validated IP without redundant DNS resolution (P10-03)
                pinnedIp = context.policyDecision().resolvedIp();
            } else {
                PolicyDecision portDecision = policyEngine.evaluate(initialUri, context.mode(), context.scopeAsset());
                if (!portDecision.allowed()) {
                    throw new PolicyViolationException(
                            "Policy violation for customPort " + customPort + ": " + portDecision.reason(),
                            List.of(new InvalidParam("customPort", portDecision.reason()))
                    );
                }
                pinnedIp = portDecision.resolvedIp();
            }
        } else {
            if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
                pinnedIp = context.policyDecision().resolvedIp();
            } else {
                PolicyDecision decision = policyEngine.evaluate(initialUri, context.mode(), context.scopeAsset());
                if (!decision.allowed()) {
                    throw new PolicyViolationException(
                            "Policy violation: " + decision.reason(),
                            List.of(new InvalidParam("targetUrl", decision.reason()))
                    );
                }
                pinnedIp = decision.resolvedIp();
            }
        }

        boolean followRedirects = Boolean.TRUE.equals(context.inputParams().get("followRedirects"));
        PinnedProbeResult result = pinnedHttpClient.executeWithRedirects(
                initialUri,
                pinnedIp,
                followRedirects,
                context.mode(),
                context.scopeAsset(),
                WIRE_CAP_BYTES,
                DECOMPRESSED_CAP_BYTES,
                READ_TIMEOUT_MS
        );

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("finalUrl", result.finalUrl());
        parsedData.put("statusCode", result.finalStatusCode());
        parsedData.put("httpVersion", result.httpVersion());
        parsedData.put("headers", result.normalizedHeaders());

        List<Map<String, Object>> cookieMaps = new ArrayList<>();
        for (ParsedCookie cookie : result.cookies()) {
            cookieMaps.add(cookie.toMap());
        }
        parsedData.put("cookies", cookieMaps);
        parsedData.put("redirectChain", result.redirectChain());

        if (result.normalizedHeaders().containsKey("server")) {
            parsedData.put("serverBanner", result.normalizedHeaders().get("server"));
        }

        List<ObservationDraft> observations = extractObservations(result);

        // Architectural invariant: score = null (scoring isolated to security_headers_score offline tool)
        return new ToolExecutionOutcome(
                result.rawOutput(),
                parsedData,
                null,
                false,
                observations
        );
    }

    private List<ObservationDraft> extractObservations(PinnedProbeResult result) {
        List<ObservationDraft> observations = new ArrayList<>();
        Map<String, Object> headers = result.normalizedHeaders();
        boolean isHttps = result.finalUrl().toLowerCase(Locale.ROOT).startsWith("https://");

        // 1. Missing Strict-Transport-Security
        if (!headers.containsKey("strict-transport-security")) {
            observations.add(new ObservationDraft(
                    "SECURITY_HEADERS",
                    "Missing Strict-Transport-Security (HSTS) header",
                    SeverityHeuristic.MEDIUM
            ));
        }

        // 2. Missing Content-Security-Policy
        if (!headers.containsKey("content-security-policy")) {
            observations.add(new ObservationDraft(
                    "SECURITY_HEADERS",
                    "Missing Content-Security-Policy header",
                    SeverityHeuristic.MEDIUM
            ));
        }

        // 3. Missing X-Content-Type-Options: nosniff
        if (!headers.containsKey("x-content-type-options")
                || !headers.get("x-content-type-options").toString().toLowerCase(Locale.ROOT).contains("nosniff")) {
            observations.add(new ObservationDraft(
                    "SECURITY_HEADERS",
                    "Missing or invalid X-Content-Type-Options header (expected 'nosniff')",
                    SeverityHeuristic.LOW
            ));
        }

        // 4. Missing X-Frame-Options (when CSP has no frame-ancestors)
        boolean hasCspFrameAncestors = false;
        if (headers.containsKey("content-security-policy")) {
            String csp = headers.get("content-security-policy").toString().toLowerCase(Locale.ROOT);
            hasCspFrameAncestors = csp.contains("frame-ancestors");
        }
        if (!headers.containsKey("x-frame-options") && !hasCspFrameAncestors) {
            observations.add(new ObservationDraft(
                    "SECURITY_HEADERS",
                    "Missing X-Frame-Options header without CSP frame-ancestors directive",
                    SeverityHeuristic.LOW
            ));
        }

        // 5. Info disclosure via Server or X-Powered-By containing version numbers
        if (headers.containsKey("server")) {
            String server = headers.get("server").toString();
            if (VERSION_PATTERN.matcher(server).matches()) {
                observations.add(new ObservationDraft(
                        "INFO_DISCLOSURE",
                        "Server header reveals software version: " + server,
                        SeverityHeuristic.LOW
                ));
            }
        }

        if (headers.containsKey("x-powered-by")) {
            String poweredBy = headers.get("x-powered-by").toString();
            if (VERSION_PATTERN.matcher(poweredBy).matches()) {
                observations.add(new ObservationDraft(
                        "INFO_DISCLOSURE",
                        "X-Powered-By header reveals software version: " + poweredBy,
                        SeverityHeuristic.LOW
                ));
            }
        }

        // 6. Set-Cookie missing HttpOnly, Secure, or SameSite
        for (ParsedCookie cookie : result.cookies()) {
            if (!cookie.httpOnly()) {
                observations.add(new ObservationDraft(
                        "COOKIE_SECURITY",
                        "Cookie '" + cookie.name() + "' is missing HttpOnly attribute",
                        SeverityHeuristic.MEDIUM
                ));
            }

            if (isHttps && !cookie.secure()) {
                observations.add(new ObservationDraft(
                        "COOKIE_SECURITY",
                        "Cookie '" + cookie.name() + "' is missing Secure attribute on HTTPS connection",
                        SeverityHeuristic.MEDIUM
                ));
            }

            if (cookie.sameSite() == null || cookie.sameSite().isBlank()) {
                observations.add(new ObservationDraft(
                        "COOKIE_SECURITY",
                        "Cookie '" + cookie.name() + "' is missing SameSite attribute",
                        SeverityHeuristic.LOW
                ));
            }
        }

        return observations;
    }

    private int parsePort(Object val) {
        if (val == null) {
            return -1;
        }
        if (val instanceof Integer i) {
            return (i >= 1 && i <= 65535) ? i : -1;
        }
        if (val instanceof Short s) {
            int i = s.intValue();
            return (i >= 1 && i <= 65535) ? i : -1;
        }
        if (val instanceof Byte b) {
            int i = b.intValue();
            return (i >= 1 && i <= 65535) ? i : -1;
        }
        if (val instanceof Long l) {
            if (l < 1 || l > 65535) {
                return -1;
            }
            return l.intValue();
        }
        if (val instanceof String s) {
            try {
                long parsed = Long.parseLong(s.trim());
                if (parsed < 1 || parsed > 65535) {
                    return -1;
                }
                return (int) parsed;
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }
}
