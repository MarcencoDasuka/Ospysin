package com.ospysin.tools.probes;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.shared.util.Utf8StringUtils;
import com.ospysin.tools.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;

/**
 * Tool #7: Internal & External Link Harvester direct probe.
 * Retrieves landing page HTML and parses anchor links into internal and external URLs,
 * and detects insecure form submission endpoints.
 */
@Component
public class ExtractLinksTool implements OspysinTool {

    public static final String TOOL_ID = "extract_links";
    public static final long WIRE_CAP_BYTES = 1024 * 1024L; // 1 MB
    public static final long DECOMPRESSED_CAP_BYTES = 2 * 1024 * 1024L; // 2 MB
    public static final int READ_TIMEOUT_MS = 15_000; // 15s

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;

    @Autowired
    public ExtractLinksTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
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

        if (params.containsKey("maxLinks")) {
            Object val = params.get("maxLinks");
            if (val == null) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("maxLinks", "maxLinks must not be null"))
                );
            }
            int maxLinks = parseInteger(val);
            if (maxLinks < 1 || maxLinks > 5000) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("maxLinks", "maxLinks must be between 1 and 5000"))
                );
            }
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        int maxLinks = 200;
        if (context.inputParams().containsKey("maxLinks") && context.inputParams().get("maxLinks") != null) {
            int parsed = parseInteger(context.inputParams().get("maxLinks"));
            if (parsed >= 1 && parsed <= 5000) {
                maxLinks = parsed;
            }
        }

        URI initialUri = URI.create(context.targetUrl().trim());

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            PolicyDecision decision = policyEngine.evaluate(initialUri, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for extract_links: " + decision.reason(),
                        List.of(new InvalidParam("targetUrl", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        PinnedProbeResult probeResult = pinnedHttpClient.executeWithRedirects(
                initialUri,
                pinnedIp,
                true,
                context.mode(),
                context.scopeAsset(),
                WIRE_CAP_BYTES,
                DECOMPRESSED_CAP_BYTES,
                READ_TIMEOUT_MS
        );

        String finalUrl = probeResult.finalUrl();
        String targetHost = extractHost(finalUrl);
        boolean isPageHttps = finalUrl.toLowerCase(Locale.ROOT).startsWith("https://");

        Set<String> internalSet = new LinkedHashSet<>();
        Set<String> externalSet = new LinkedHashSet<>();
        Set<String> formActionsSet = new LinkedHashSet<>();
        List<String> insecureForms = new ArrayList<>();

        if (!probeResult.bodyText().isBlank()) {
            Document doc = Jsoup.parse(probeResult.bodyText(), finalUrl);

            // 1. Harvest <a href="...">
            Elements anchors = doc.select("a[href]");
            for (Element anchor : anchors) {
                String rawHref = anchor.attr("href").trim();
                if (rawHref.isBlank() || rawHref.startsWith("#") || isIgnoredScheme(rawHref)) {
                    continue;
                }

                String href = anchor.absUrl("href").trim();
                if (href.isBlank()) {
                    href = rawHref;
                }

                if (isIgnoredScheme(href)) {
                    continue;
                }

                try {
                    String lowerHref = href.toLowerCase(Locale.ROOT);
                    if (!lowerHref.startsWith("http://") && !lowerHref.startsWith("https://")) {
                        continue;
                    }
                    String linkHost = extractHost(href);
                    if (linkHost.isEmpty()) {
                        continue;
                    }

                    if (!targetHost.isEmpty() && linkHost.equalsIgnoreCase(targetHost)) {
                        internalSet.add(href);
                    } else {
                        externalSet.add(href);
                    }
                } catch (Exception ignored) {
                }
            }

            // 2. Harvest <form action="...">
            Elements forms = doc.select("form");
            for (Element form : forms) {
                String action = form.absUrl("action").trim();
                if (action.isBlank()) {
                    action = form.attr("action").trim();
                }
                if (action.isBlank()) {
                    action = finalUrl;
                }

                formActionsSet.add(action);

                if (isPageHttps && action.toLowerCase(Locale.ROOT).startsWith("http://")) {
                    insecureForms.add(action);
                }
            }
        }

        int totalInternalCount = internalSet.size();
        int totalExternalCount = externalSet.size();

        List<String> internalLinks = internalSet.stream().limit(maxLinks).toList();
        List<String> externalLinks = externalSet.stream().limit(maxLinks).toList();
        List<String> formActions = new ArrayList<>(formActionsSet);

        List<ObservationDraft> observations = new ArrayList<>();
        for (String insecureFormUrl : insecureForms) {
            observations.add(new ObservationDraft(
                    "CONTENT_SECURITY",
                    "Form action submits data over unencrypted HTTP: " + insecureFormUrl,
                    SeverityHeuristic.MEDIUM
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("statusCode", probeResult.finalStatusCode());
        parsedData.put("internalLinks", internalLinks);
        parsedData.put("externalLinks", externalLinks);
        parsedData.put("formActions", formActions);
        parsedData.put("totalInternalCount", totalInternalCount);
        parsedData.put("totalExternalCount", totalExternalCount);

        String combinedRaw = probeResult.rawOutput();
        if (!probeResult.bodyText().isEmpty()) {
            combinedRaw += "\r\n\r\n" + probeResult.bodyText();
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

    private boolean isIgnoredScheme(String url) {
        if (url == null || url.isBlank() || url.startsWith("#")) {
            return true;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("javascript:")
                || lower.startsWith("mailto:")
                || lower.startsWith("tel:")
                || lower.startsWith("data:");
    }

    private String extractHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            String cleanUrl = url.trim();
            int queryIdx = cleanUrl.indexOf('?');
            if (queryIdx >= 0) {
                cleanUrl = cleanUrl.substring(0, queryIdx);
            }
            int fragmentIdx = cleanUrl.indexOf('#');
            if (fragmentIdx >= 0) {
                cleanUrl = cleanUrl.substring(0, fragmentIdx);
            }
            URI u = URI.create(cleanUrl);
            String h = u.getHost();
            if (h == null) {
                String auth = u.getAuthority();
                if (auth != null) {
                    int at = auth.indexOf('@');
                    if (at >= 0) {
                        auth = auth.substring(at + 1);
                    }
                    int closeBracket = auth.indexOf(']');
                    int colon = auth.lastIndexOf(':');
                    if (colon > closeBracket) {
                        h = auth.substring(0, colon);
                    } else {
                        h = auth;
                    }
                }
            }
            if (h == null) {
                return "";
            }
            String host = h.trim();
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            while (host.endsWith(".") && host.length() > 1) {
                host = host.substring(0, host.length() - 1);
            }
            return host.toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    private int parseInteger(Object val) {
        if (val == null || val instanceof Float || val instanceof Double) return -1;
        if (val instanceof Integer i) return i;
        if (val instanceof Short s) return s.intValue();
        if (val instanceof Byte b) return b.intValue();
        if (val instanceof Long l) return (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) ? l.intValue() : -1;
        if (val instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }
}
