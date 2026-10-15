package com.ospysin.tools.probes;

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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.URI;
import java.util.*;

/**
 * Tool #6: Sitemap Structure Parser direct probe.
 * Fetches and parses sitemap.xml to enumerate endpoints and sensitive paths using an XXE-hardened XML parser.
 */
@Component
public class SitemapXmlTool implements OspysinTool {

    private static final Logger log = LoggerFactory.getLogger(SitemapXmlTool.class);

    public static final String TOOL_ID = "sitemap_xml";
    public static final long WIRE_CAP_BYTES = 512 * 1024L; // 512 KB
    public static final long DECOMPRESSED_CAP_BYTES = 512 * 1024L; // 512 KB
    public static final int READ_TIMEOUT_MS = 15_000; // 15s

    private static final List<String> SENSITIVE_KEYWORDS = List.of(
            "/admin", "/login", "/auth", "/debug", "/actuator",
            "/swagger", "/api", "/config", "/backup", "/internal"
    );

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;

    @Autowired
    public SitemapXmlTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
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

        List<InvalidParam> invalidParams = new ArrayList<>();

        if (params.containsKey("customPath")) {
            Object val = params.get("customPath");
            if (val == null || !(val instanceof String s) || s.isBlank() || !s.startsWith("/") || s.startsWith("//")
                    || s.contains("..") || s.contains("\\") || s.contains("\r") || s.contains("\n")
                    || s.contains("://") || s.length() > 255) {
                invalidParams.add(new InvalidParam("customPath",
                        "customPath must be a non-null, non-blank string starting with '/', not start with '//', not contain '..', '\\', CR, LF, or '://', and length must be <= 255"));
            }
        }

        if (params.containsKey("maxUrls")) {
            Object val = params.get("maxUrls");
            if (val == null) {
                invalidParams.add(new InvalidParam("maxUrls", "maxUrls must not be null"));
            } else {
                int maxUrls = parseInteger(val);
                if (maxUrls < 1 || maxUrls > 1000) {
                    invalidParams.add(new InvalidParam("maxUrls", "maxUrls must be between 1 and 1000"));
                }
            }
        }

        if (!invalidParams.isEmpty()) {
            throw new ValidationException("Validation error for " + TOOL_ID, invalidParams);
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        String customPath = "/sitemap.xml";
        if (context.inputParams().containsKey("customPath") && context.inputParams().get("customPath") != null) {
            String p = context.inputParams().get("customPath").toString().trim();
            if (!p.isBlank()) {
                customPath = p;
            }
        }

        int maxUrls = 500;
        if (context.inputParams().containsKey("maxUrls") && context.inputParams().get("maxUrls") != null) {
            int parsed = parseInteger(context.inputParams().get("maxUrls"));
            if (parsed >= 1 && parsed <= 1000) {
                maxUrls = parsed;
            }
        }

        URI baseUri = URI.create(context.targetUrl().trim());
        URI sitemapUri = baseUri.resolve(customPath);

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            PolicyDecision decision = policyEngine.evaluate(sitemapUri, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for sitemap.xml: " + decision.reason(),
                        List.of(new InvalidParam("targetUrl", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        PinnedProbeResult probeResult = pinnedHttpClient.executeWithRedirects(
                sitemapUri,
                pinnedIp,
                true,
                context.mode(),
                context.scopeAsset(),
                WIRE_CAP_BYTES,
                DECOMPRESSED_CAP_BYTES,
                READ_TIMEOUT_MS
        );

        int statusCode = probeResult.finalStatusCode();
        boolean found = false;
        List<String> sampleUrls = new ArrayList<>();
        List<String> sitemapIndexUrls = new ArrayList<>();
        List<String> sensitivePathsFound = new ArrayList<>();

        if (statusCode == 200 && probeResult.bodyBytes().length > 0) {
            try {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                // Strict XXE & Billion Laughs defenses
                dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
                dbf.setXIncludeAware(false);
                dbf.setExpandEntityReferences(false);

                DocumentBuilder db = dbf.newDocumentBuilder();
                Document doc = db.parse(new ByteArrayInputStream(probeResult.bodyBytes()));
                doc.getDocumentElement().normalize();

                found = true;
                parseSitemapDocument(doc, maxUrls, sampleUrls, sitemapIndexUrls, sensitivePathsFound);
            } catch (Exception e) {
                log.warn("Failed to parse sitemap XML safely (possible malformed content or disallowed DOCTYPE/XXE): {}", e.getMessage());
                found = false;
            }
        }

        List<ObservationDraft> observations = new ArrayList<>();
        if (!sensitivePathsFound.isEmpty()) {
            observations.add(new ObservationDraft(
                    "RECON_SITEMAP",
                    "Sitemap exposes sensitive or administrative endpoint(s): " + String.join(", ", sensitivePathsFound),
                    SeverityHeuristic.LOW
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("found", found);
        parsedData.put("statusCode", statusCode);
        parsedData.put("urlCount", sampleUrls.size());
        parsedData.put("sampleUrls", sampleUrls);
        parsedData.put("sitemapIndexUrls", sitemapIndexUrls);
        parsedData.put("sensitivePathsFound", sensitivePathsFound);

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

    private void parseSitemapDocument(Document doc,
                                      int maxUrls,
                                      List<String> sampleUrls,
                                      List<String> sitemapIndexUrls,
                                      List<String> sensitivePathsFound) {
        Set<String> sensitiveSet = new LinkedHashSet<>();

        // 1. Sitemap index links (<sitemap><loc>...</loc></sitemap>)
        NodeList sitemapNodes = doc.getElementsByTagName("sitemap");
        for (int i = 0; i < sitemapNodes.getLength(); i++) {
            Node node = sitemapNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element el = (Element) node;
                NodeList locs = el.getElementsByTagName("loc");
                if (locs.getLength() > 0) {
                    String locText = locs.item(0).getTextContent().trim();
                    if (!locText.isEmpty() && !sitemapIndexUrls.contains(locText)) {
                        sitemapIndexUrls.add(locText);
                    }
                }
            }
        }

        // 2. Individual URL entries (<url><loc>...</loc></url>)
        NodeList urlNodes = doc.getElementsByTagName("url");
        int totalUrlCount = urlNodes.getLength();
        int limit = Math.min(totalUrlCount, maxUrls);

        for (int i = 0; i < limit; i++) {
            Node node = urlNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element el = (Element) node;
                NodeList locs = el.getElementsByTagName("loc");
                if (locs.getLength() > 0) {
                    String locText = locs.item(0).getTextContent().trim();
                    if (!locText.isEmpty()) {
                        sampleUrls.add(locText);
                        String path = locText;
                        try {
                            URI u = URI.create(locText.trim());
                            if (u.getPath() != null) {
                                path = u.getPath();
                            }
                        } catch (Exception ignored) {
                        }
                        for (String kw : SENSITIVE_KEYWORDS) {
                            if (matchesSensitiveKeyword(path, kw)) {
                                sensitiveSet.add(locText);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 3. Fallback for flat <loc> tags if no <url> or <sitemap> containers exist
        if (urlNodes.getLength() == 0 && sitemapNodes.getLength() == 0) {
            NodeList directLocs = doc.getElementsByTagName("loc");
            int directLimit = Math.min(directLocs.getLength(), maxUrls);
            for (int i = 0; i < directLimit; i++) {
                String locText = directLocs.item(i).getTextContent().trim();
                if (!locText.isEmpty()) {
                    sampleUrls.add(locText);
                    String path = locText;
                    try {
                        URI u = URI.create(locText.trim());
                        if (u.getPath() != null) {
                            path = u.getPath();
                        }
                    } catch (Exception ignored) {
                    }
                    for (String kw : SENSITIVE_KEYWORDS) {
                        if (matchesSensitiveKeyword(path, kw)) {
                            sensitiveSet.add(locText);
                            break;
                        }
                    }
                }
            }
        }

        sensitivePathsFound.addAll(sensitiveSet);
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
