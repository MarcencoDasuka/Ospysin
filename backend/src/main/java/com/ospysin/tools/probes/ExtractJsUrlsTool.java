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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool #8: JavaScript Asset Harvester direct probe.
 * Discovers and parses script tags to catalog loaded client-side JavaScript bundles,
 * flags third-party scripts lacking SRI, and discovers API endpoints in inline scripts.
 */
@Component
public class ExtractJsUrlsTool implements OspysinTool {

    public static final String TOOL_ID = "extract_js_urls";
    public static final long WIRE_CAP_BYTES = 1024 * 1024L; // 1 MB
    public static final long DECOMPRESSED_CAP_BYTES = 2 * 1024 * 1024L; // 2 MB
    public static final int READ_TIMEOUT_MS = 15_000; // 15s

    private static final Pattern API_ROUTE_PATTERN = Pattern.compile("(?<![a-zA-Z0-9_])(?:/api/|/v1/|/v2/|/v3/|/graphql|/auth/|/admin/)[a-zA-Z0-9_\\-/]*");

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;

    @Autowired
    public ExtractJsUrlsTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        // extract_js_urls takes no required or optional parameters
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
                        "Policy violation for extract_js_urls: " + decision.reason(),
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

        List<Map<String, Object>> scripts = new ArrayList<>();
        Set<String> seenSrcs = new HashSet<>();
        int inlineScriptsCount = 0;
        Set<String> discoveredEndpointsSet = new LinkedHashSet<>();
        List<ObservationDraft> observations = new ArrayList<>();

        if (!probeResult.bodyText().isBlank()) {
            Document doc = Jsoup.parse(probeResult.bodyText(), finalUrl);
            Elements scriptElements = doc.select("script");

            for (Element script : scriptElements) {
                String src = script.absUrl("src").trim();
                if (src.isBlank()) {
                    src = script.attr("src").trim();
                }

                if (!src.isBlank()) {
                    String lowerSrc = src.toLowerCase(Locale.ROOT);
                    if (lowerSrc.startsWith("javascript:") || lowerSrc.startsWith("data:")
                            || lowerSrc.startsWith("blob:") || lowerSrc.startsWith("mailto:")
                            || lowerSrc.startsWith("tel:")) {
                        continue;
                    }
                    if (!lowerSrc.startsWith("http://") && !lowerSrc.startsWith("https://")) {
                        continue;
                    }
                    String scriptHost = extractHost(src);
                    if (scriptHost.isEmpty()) {
                        continue;
                    }

                    if (seenSrcs.add(src)) {
                        boolean isInternal = !targetHost.isEmpty() && scriptHost.equalsIgnoreCase(targetHost);
                        boolean hasIntegrity = script.hasAttr("integrity") && !script.attr("integrity").isBlank();

                        Map<String, Object> scriptInfo = new LinkedHashMap<>();
                        scriptInfo.put("src", src);
                        scriptInfo.put("isInternal", isInternal);
                        scriptInfo.put("hasIntegrity", hasIntegrity);
                        scripts.add(scriptInfo);

                        if (!isInternal && !hasIntegrity) {
                            observations.add(new ObservationDraft(
                                    "SCRIPT_SECURITY",
                                    "External script loaded without Subresource Integrity (SRI): " + src,
                                    SeverityHeuristic.LOW
                            ));
                        }
                    }
                } else {
                    inlineScriptsCount++;
                    String scriptContent = script.data();
                    if (scriptContent.isBlank()) {
                        scriptContent = script.html();
                    }
                    if (!scriptContent.isBlank()) {
                        Matcher matcher = API_ROUTE_PATTERN.matcher(scriptContent);
                        while (matcher.find()) {
                            discoveredEndpointsSet.add(matcher.group());
                        }
                    }
                }
            }
        }

        List<String> discoveredEndpoints = new ArrayList<>(discoveredEndpointsSet);
        if (!discoveredEndpoints.isEmpty()) {
            observations.add(new ObservationDraft(
                    "RECON_ENDPOINTS",
                    "Discovered API endpoint route(s) in inline scripts: " + String.join(", ", discoveredEndpoints),
                    SeverityHeuristic.INFO
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("statusCode", probeResult.finalStatusCode());
        parsedData.put("scripts", scripts);
        parsedData.put("inlineScriptsCount", inlineScriptsCount);
        parsedData.put("discoveredEndpoints", discoveredEndpoints);

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
}
