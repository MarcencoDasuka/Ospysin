package com.ospysin.tools.probes;

import com.ospysin.execution.HostRateLimiter;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.shared.util.Utf8StringUtils;
import com.ospysin.tools.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.util.*;

/**
 * Tool #13: CORS Misconfiguration & Origin Probe direct probe.
 * Directly tests the target application's Cross-Origin Resource Sharing implementation
 * against unverified origins to detect trust misconfigurations combined with credentials.
 */
@Component
public class CorsMisconfigCheckTool implements OspysinTool {

    private static final Logger log = LoggerFactory.getLogger(CorsMisconfigCheckTool.class);

    public static final String TOOL_ID = "cors_misconfig_check";
    public static final long WIRE_CAP_BYTES = 32 * 1024L; // 32 KB
    public static final long DECOMPRESSED_CAP_BYTES = 32 * 1024L; // 32 KB
    public static final int READ_TIMEOUT_MS = 10_000; // 10s

    public static final String DEFAULT_REMEDIATION =
            "Do not reflect arbitrary Origin headers. Maintain an explicit allowlist of trusted origins.";

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;
    private final HostRateLimiter hostRateLimiter;

    @Autowired
    public CorsMisconfigCheckTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine, HostRateLimiter hostRateLimiter) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.hostRateLimiter = hostRateLimiter;
    }

    public CorsMisconfigCheckTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
        this(pinnedHttpClient, policyEngine, null);
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        if (params == null || params.isEmpty()) {
            return;
        }

        List<InvalidParam> errors = new ArrayList<>();

        if (params.containsKey("customOrigins")) {
            Object val = params.get("customOrigins");
            if (val == null) {
                errors.add(new InvalidParam("customOrigins", "customOrigins must not be null"));
            } else if (!(val instanceof List<?> list)) {
                errors.add(new InvalidParam("customOrigins", "customOrigins must be a list"));
            } else {
                if (list.size() > 10) {
                    errors.add(new InvalidParam("customOrigins", "customOrigins list must contain at most 10 origins"));
                }
                for (int i = 0; i < list.size(); i++) {
                    Object item = list.get(i);
                    if (!(item instanceof String s) || s.isBlank() || s.length() > 255
                            || s.contains("\r") || s.contains("\n")) {
                        errors.add(new InvalidParam("customOrigins", "Origin at index " + i + " must be a non-blank string <= 255 chars without CRLF"));
                        break;
                    }
                    String trimmed = s.trim();
                    if (!"null".equalsIgnoreCase(trimmed)) {
                        try {
                            URI uri = URI.create(trimmed);
                            String scheme = uri.getScheme();
                            if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
                                errors.add(new InvalidParam("customOrigins", "Origin at index " + i + " must have http or https scheme"));
                                break;
                            }
                            if (uri.getHost() == null || uri.getHost().isBlank()) {
                                errors.add(new InvalidParam("customOrigins", "Origin at index " + i + " must specify a valid host"));
                                break;
                            }
                            if (uri.getRawPath() != null && !uri.getRawPath().isEmpty() && !uri.getRawPath().equals("/")) {
                                errors.add(new InvalidParam("customOrigins", "Origin at index " + i + " must not contain path elements"));
                                break;
                            }
                            if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
                                errors.add(new InvalidParam("customOrigins", "Origin at index " + i + " must not contain query or fragment"));
                                break;
                            }
                        } catch (Exception ex) {
                            errors.add(new InvalidParam("customOrigins", "Origin at index " + i + " is malformed: " + ex.getMessage()));
                            break;
                        }
                    }
                }
            }
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Parameter validation failed for cors_misconfig_check", errors);
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        URI initialUri = URI.create(context.targetUrl().trim());

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            PolicyDecision decision = policyEngine.evaluate(initialUri, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for cors_misconfig_check: " + decision.reason(),
                        List.of(new InvalidParam("targetUrl", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        String scheme = initialUri.getScheme() != null ? initialUri.getScheme() : "http";
        String targetHost = initialUri.getHost();
        if (targetHost == null || targetHost.isBlank()) {
            targetHost = "example.com";
        }

        Map<String, Object> inputParams = context.inputParams();
        @SuppressWarnings("unchecked")
        List<String> customOriginsList = (List<String>) inputParams.get("customOrigins");

        // Build list of test origins
        Set<String> testOriginsSet = new LinkedHashSet<>();
        testOriginsSet.add("https://attacker.com");
        testOriginsSet.add("null");
        if (!targetHost.contains(":") && !targetHost.contains("[") && !targetHost.contains("]")) {
            testOriginsSet.add(scheme + "://" + targetHost + ".attacker.com");
            testOriginsSet.add(scheme + "://evil-" + targetHost);
        }

        if (customOriginsList != null) {
            for (String custom : customOriginsList) {
                if (custom != null && !custom.isBlank()) {
                    testOriginsSet.add(custom.trim());
                }
            }
        }

        List<Map<String, Object>> probes = new ArrayList<>();
        List<ObservationDraft> observations = new ArrayList<>();
        StringBuilder rawTrace = new StringBuilder();

        boolean anyVulnerable = false;
        String highestVulnerabilityType = "NONE";
        String highestSeverity = "INFO";

        for (String testedOrigin : testOriginsSet) {
            rawTrace.append("PROBE Origin: ").append(testedOrigin).append("\n");

            if (hostRateLimiter != null) {
                hostRateLimiter.acquire(targetHost);
            }

            try {
                PinnedHttpResponse response = pinnedHttpClient.executeSingle(
                        initialUri,
                        pinnedIp,
                        Map.of("Origin", testedOrigin),
                        WIRE_CAP_BYTES,
                        DECOMPRESSED_CAP_BYTES,
                        READ_TIMEOUT_MS,
                        null
                );

                String reflectedOrigin = getHeader(response.headers(), "access-control-allow-origin");
                String acac = getHeader(response.headers(), "access-control-allow-credentials");
                boolean allowCredentials = "true".equalsIgnoreCase(acac);

                rawTrace.append("  <- HTTP ").append(response.statusCode())
                        .append(", ACAO: ").append(reflectedOrigin)
                        .append(", ACAC: ").append(acac).append("\n");

                boolean exploitable = false;
                String type = null;
                String severity = null;

                if (reflectedOrigin != null) {
                    String normReflected = reflectedOrigin.trim();
                    if ("https://attacker.com".equalsIgnoreCase(testedOrigin) && normReflected.equalsIgnoreCase(testedOrigin)) {
                        if (allowCredentials) {
                            exploitable = true;
                            type = "ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS";
                            severity = "HIGH";
                        } else {
                            exploitable = false;
                            type = "ARBITRARY_ORIGIN_REFLECTION";
                            severity = "MEDIUM";
                        }
                    } else if ("null".equalsIgnoreCase(testedOrigin) && "null".equalsIgnoreCase(normReflected)) {
                        if (allowCredentials) {
                            exploitable = true;
                            type = "NULL_ORIGIN_ALLOWED_WITH_CREDENTIALS";
                            severity = "HIGH";
                        } else {
                            exploitable = false;
                            type = "NULL_ORIGIN_ALLOWED";
                            severity = "LOW";
                        }
                    } else if ((testedOrigin.endsWith(".attacker.com") || testedOrigin.contains("evil-"))
                            && normReflected.equalsIgnoreCase(testedOrigin)) {
                        if (allowCredentials) {
                            exploitable = true;
                            type = "TRUST_BOUNDARY_BYPASS_WITH_CREDENTIALS";
                            severity = "HIGH";
                        } else {
                            exploitable = false;
                            type = "TRUST_BOUNDARY_BYPASS";
                            severity = "MEDIUM";
                        }
                    } else if ("*".equals(normReflected)) {
                        if (allowCredentials) {
                            exploitable = true;
                            type = "WILDCARD_ORIGIN_WITH_CREDENTIALS";
                            severity = "MEDIUM";
                        }
                    } else if (customOriginsList != null && customOriginsList.contains(testedOrigin)
                            && normReflected.equalsIgnoreCase(testedOrigin)) {
                        if (allowCredentials) {
                            exploitable = true;
                            type = "CUSTOM_ORIGIN_ALLOWED_WITH_CREDENTIALS";
                            severity = "HIGH";
                        } else {
                            exploitable = false;
                            type = "CUSTOM_ORIGIN_ALLOWED";
                            severity = "LOW";
                        }
                    }
                }

                if (type != null) {
                    anyVulnerable = true;
                    if (isHigherSeverity(severity, highestSeverity)) {
                        highestSeverity = severity;
                        highestVulnerabilityType = type;
                    }
                }

                Map<String, Object> probeMap = new LinkedHashMap<>();
                probeMap.put("testedOrigin", testedOrigin);
                probeMap.put("reflectedOrigin", reflectedOrigin);
                probeMap.put("allowCredentials", allowCredentials);
                probeMap.put("exploitable", exploitable);
                probes.add(probeMap);

            } catch (IOException ex) {
                log.debug("I/O error probing origin {}: {}", testedOrigin, ex.getMessage());
                rawTrace.append("  <- ERROR: ").append(ex.getMessage()).append("\n");

                Map<String, Object> probeMap = new LinkedHashMap<>();
                probeMap.put("testedOrigin", testedOrigin);
                probeMap.put("reflectedOrigin", null);
                probeMap.put("allowCredentials", false);
                probeMap.put("exploitable", false);
                probes.add(probeMap);
            }
        }

        if (anyVulnerable) {
            observations.add(new ObservationDraft(
                    "CORS_MISCONFIG",
                    "Cross-Origin Resource Sharing (CORS) misconfiguration detected on " + context.targetUrl() + " (" + highestVulnerabilityType + ")",
                    toSeverityHeuristic(highestSeverity)
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("isVulnerable", anyVulnerable);
        parsedData.put("vulnerabilityType", highestVulnerabilityType);
        parsedData.put("severity", highestSeverity);
        parsedData.put("probes", probes);
        parsedData.put("remediation", DEFAULT_REMEDIATION);

        String truncatedRaw = Utf8StringUtils.truncateUtf8(rawTrace.toString(), Utf8StringUtils.MAX_RAW_OUTPUT_BYTES);

        return new ToolExecutionOutcome(
                truncatedRaw,
                parsedData,
                null,
                false,
                observations
        );
    }

    private static boolean isHigherSeverity(String cand, String curr) {
        return severityRank(cand) > severityRank(curr);
    }

    private static int severityRank(String sev) {
        if (sev == null) return 0;
        return switch (sev.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    private static SeverityHeuristic toSeverityHeuristic(String severity) {
        if (severity == null) {
            return SeverityHeuristic.MEDIUM;
        }
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "HIGH" -> SeverityHeuristic.HIGH;
            case "LOW" -> SeverityHeuristic.LOW;
            case "INFO" -> SeverityHeuristic.INFO;
            default -> SeverityHeuristic.MEDIUM;
        };
    }

    private static String getHeader(Map<String, List<String>> headers, String name) {
        if (headers == null) return null;
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        if (values != null && !values.isEmpty()) {
            return values.get(0);
        }
        return null;
    }
}
