package com.ospysin.tools.probes;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.shared.util.Utf8StringUtils;
import com.ospysin.tools.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;

/**
 * Tool #5: Robots.txt Disallow Inspection direct probe.
 * Retrieves /robots.txt to inspect declared user-agents, disallow/allow rules, and sitemap references.
 */
@Component
public class RobotsTxtTool implements OspysinTool {

    public static final String TOOL_ID = "robots_txt";
    public static final long WIRE_CAP_BYTES = 128 * 1024L; // 128 KB
    public static final long DECOMPRESSED_CAP_BYTES = 128 * 1024L; // 128 KB
    public static final int READ_TIMEOUT_MS = 10_000; // 10s

    private static final List<String> SENSITIVE_KEYWORDS = List.of(
            "/admin", "/auth", "/login", "/api", "/backup", "/db", "/config", "/.git", "/.env",
            "/actuator", "/swagger", "/api-docs", "/private", "/internal",
            "/debug", "/wp-admin", "/phpmyadmin"
    );

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;

    @Autowired
    public RobotsTxtTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        // robots_txt takes no required or optional parameters
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        URI baseUri = URI.create(context.targetUrl().trim());
        URI robotsUri = baseUri.resolve("/robots.txt");

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            PolicyDecision decision = policyEngine.evaluate(robotsUri, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for robots.txt: " + decision.reason(),
                        List.of(new InvalidParam("targetUrl", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        PinnedProbeResult probeResult = pinnedHttpClient.executeWithRedirects(
                robotsUri,
                pinnedIp,
                true,
                context.mode(),
                context.scopeAsset(),
                WIRE_CAP_BYTES,
                DECOMPRESSED_CAP_BYTES,
                READ_TIMEOUT_MS
        );

        int statusCode = probeResult.finalStatusCode();
        String body = probeResult.bodyText();

        boolean isHtmlSoft404 = false;
        String trimmedBody = body.trim().toLowerCase(Locale.ROOT);
        if (trimmedBody.startsWith("<!doctype html") || trimmedBody.startsWith("<html") || trimmedBody.startsWith("<?xml")) {
            isHtmlSoft404 = true;
        }

        boolean found = (statusCode == 200 && !isHtmlSoft404);

        Map<String, Map<String, List<String>>> userAgents = new LinkedHashMap<>();
        List<String> sitemaps = new ArrayList<>();
        List<String> sensitivePaths = new ArrayList<>();

        if (found) {
            parseRobotsTxt(body, userAgents, sitemaps, sensitivePaths);
        }

        List<ObservationDraft> observations = new ArrayList<>();
        if (!sensitivePaths.isEmpty()) {
            observations.add(new ObservationDraft(
                    "RECON_ROBOTS",
                    "robots.txt discloses sensitive path(s): " + String.join(", ", sensitivePaths),
                    SeverityHeuristic.MEDIUM
            ));
        }
        if (!sitemaps.isEmpty()) {
            observations.add(new ObservationDraft(
                    "RECON_ROBOTS",
                    "robots.txt declares " + sitemaps.size() + " sitemap(s)",
                    SeverityHeuristic.INFO
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("found", found);
        parsedData.put("statusCode", statusCode);
        parsedData.put("userAgents", userAgents);
        parsedData.put("sitemaps", sitemaps);
        parsedData.put("sensitivePaths", sensitivePaths);

        String combinedRaw = probeResult.rawOutput();
        if (!body.isEmpty()) {
            combinedRaw += "\r\n\r\n" + body;
        }
        String truncatedRaw = Utf8StringUtils.truncateUtf8(combinedRaw, Utf8StringUtils.MAX_RAW_OUTPUT_BYTES);

        return new ToolExecutionOutcome(
                truncatedRaw,
                parsedData,
                null,
                false,
                observations
        );
    }

    private void parseRobotsTxt(String body,
                                Map<String, Map<String, List<String>>> userAgents,
                                List<String> sitemaps,
                                List<String> sensitivePaths) {
        Set<String> sensitivePathsSet = new LinkedHashSet<>();
        List<String> currentUserAgents = new ArrayList<>();
        boolean lastDirectiveWasOther = false;

        String[] lines = body.split("\\r?\\n");
        for (String rawLine : lines) {
            String line = rawLine;
            int hashIdx = line.indexOf('#');
            if (hashIdx >= 0) {
                line = line.substring(0, hashIdx);
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            int colonIdx = line.indexOf(':');
            if (colonIdx <= 0) {
                continue;
            }

            String directive = line.substring(0, colonIdx).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colonIdx + 1).trim();

            switch (directive) {
                case "user-agent" -> {
                    if (lastDirectiveWasOther) {
                        currentUserAgents.clear();
                    }
                    currentUserAgents.add(value);
                    userAgents.computeIfAbsent(value, ua -> {
                        Map<String, List<String>> m = new LinkedHashMap<>();
                        m.put("disallowed", new ArrayList<>());
                        m.put("allowed", new ArrayList<>());
                        return m;
                    });
                    lastDirectiveWasOther = false;
                }
                case "disallow" -> {
                    lastDirectiveWasOther = true;
                    if (currentUserAgents.isEmpty()) {
                        currentUserAgents.add("*");
                        userAgents.computeIfAbsent("*", ua -> {
                            Map<String, List<String>> m = new LinkedHashMap<>();
                            m.put("disallowed", new ArrayList<>());
                            m.put("allowed", new ArrayList<>());
                            return m;
                        });
                    }
                    if (!value.isEmpty()) {
                        for (String ua : currentUserAgents) {
                            userAgents.get(ua).get("disallowed").add(value);
                        }
                        for (String kw : SENSITIVE_KEYWORDS) {
                            if (matchesSensitiveKeyword(value, kw)) {
                                sensitivePathsSet.add(value);
                                break;
                            }
                        }
                    }
                }
                case "allow" -> {
                    lastDirectiveWasOther = true;
                    if (currentUserAgents.isEmpty()) {
                        currentUserAgents.add("*");
                        userAgents.computeIfAbsent("*", ua -> {
                            Map<String, List<String>> m = new LinkedHashMap<>();
                            m.put("disallowed", new ArrayList<>());
                            m.put("allowed", new ArrayList<>());
                            return m;
                        });
                    }
                    if (!value.isEmpty()) {
                        for (String ua : currentUserAgents) {
                            userAgents.get(ua).get("allowed").add(value);
                        }
                    }
                }
                case "sitemap" -> {
                    lastDirectiveWasOther = true;
                    if (!value.isEmpty() && !sitemaps.contains(value)) {
                        sitemaps.add(value);
                    }
                }
                default -> lastDirectiveWasOther = true;
            }
        }

        sensitivePaths.addAll(sensitivePathsSet);
    }

    public static boolean matchesSensitiveKeyword(String path, String keyword) {
        if (path == null || keyword == null || path.isBlank() || keyword.isBlank()) {
            return false;
        }
        String p = path.toLowerCase(Locale.ROOT).trim();
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        int h = p.indexOf('#');
        if (h >= 0) {
            p = p.substring(0, h);
        }

        String kw = keyword.toLowerCase(Locale.ROOT).trim();
        int idx = 0;
        while ((idx = p.indexOf(kw, idx)) != -1) {
            boolean validStart = (idx == 0 || p.charAt(idx - 1) == '/');
            if (validStart) {
                int endIdx = idx + kw.length();
                if (endIdx == p.length()) {
                    return true;
                }
                char nextChar = p.charAt(endIdx);
                if (nextChar == '/' || nextChar == '?' || nextChar == '#' || nextChar == '.'
                        || nextChar == '-' || nextChar == '_' || nextChar == '*') {
                    return true;
                }
            }
            idx += kw.length();
        }
        return false;
    }
}
