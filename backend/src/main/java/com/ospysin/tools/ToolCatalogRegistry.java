package com.ospysin.tools;

import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Authoritative registry for all canonical tools in Ospysin and their SPI implementations.
 */
@Component
public class ToolCatalogRegistry {

    private final Map<String, ToolMetadata> metadataMap = new LinkedHashMap<>();
    private final Map<String, OspysinTool> toolBeans = new ConcurrentHashMap<>();

    @Autowired
    public ToolCatalogRegistry(@Autowired(required = false) List<OspysinTool> tools) {
        registerCanonicalMetadata();
        if (tools != null) {
            for (OspysinTool tool : tools) {
                registerToolBean(tool);
            }
        }
    }

    private void registerCanonicalMetadata() {
        // 1. External Third-Party Recon (2 tools)
        register(new ToolMetadata(
                "dns_lookup",
                "DNS Record Enumeration",
                "DNS",
                ExecutionType.THIRD_PARTY_RECON,
                "Queries primary resource records (A, AAAA, MX, TXT, NS, CNAME) for the target domain.",
                Map.of("recordTypes", List.of("A", "AAAA", "MX", "TXT", "NS"))
        ));

        register(new ToolMetadata(
                "whois_lookup",
                "WHOIS / RDAP Registration",
                "WHOIS",
                ExecutionType.THIRD_PARTY_RECON,
                "Queries authoritative WHOIS / RDAP registration directories for domain lifecycle and registrar records.",
                Map.of("referralDepth", 1)
        ));

        // 2. Active Direct Target Probes (11 tools)
        register(new ToolMetadata(
                "tls_info",
                "TLS/SSL Handshake & Cipher Suite",
                "TLS",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Establishes a direct TLS handshake to inspect peer certificates, cipher suites, and protocol versions.",
                Map.of("port", 443)
        ));

        Map<String, Object> httpHeadersSchema = new LinkedHashMap<>();
        httpHeadersSchema.put("customPort", null);
        httpHeadersSchema.put("followRedirects", false);
        register(new ToolMetadata(
                "http_headers",
                "HTTP Headers & Cookies",
                "HTTP",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Fetches and analyzes HTTP response headers, cookies, security posture, and server banners.",
                httpHeadersSchema
        ));

        register(new ToolMetadata(
                "robots_txt",
                "Robots.txt Disallow Inspection",
                "RECON",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Retrieves /robots.txt and parses user-agents, disallow rules, and declared sitemaps.",
                Map.of()
        ));

        register(new ToolMetadata(
                "sitemap_xml",
                "Sitemap Structure Parser",
                "RECON",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Fetches and parses sitemap.xml to enumerate endpoints and sensitive paths.",
                Map.of("customPath", "/sitemap.xml", "maxUrls", 500)
        ));

        register(new ToolMetadata(
                "extract_links",
                "Internal & External Link Harvester",
                "CONTENT",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Retrieves landing page HTML and parses anchor links into internal and external URLs.",
                Map.of("maxLinks", 200)
        ));

        register(new ToolMetadata(
                "extract_js_urls",
                "JavaScript Asset Harvester",
                "CONTENT",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Discovers and parses script tags to catalog loaded client-side JavaScript bundles.",
                Map.of()
        ));

        register(new ToolMetadata(
                "tech_detect",
                "Technology Fingerprint Heuristics",
                "RECON",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Probes responses to identify underlying web servers, frameworks, and CMS platforms.",
                Map.of()
        ));

        register(new ToolMetadata(
                "sensitive_files_check",
                "Exposed Sensitive Files & Endpoints",
                "SECURITY",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Probes target server directly for known sensitive files, backup archives, and debug endpoints.",
                Map.of("customPaths", List.of(), "stopOnFirstExposed", false)
        ));

        register(new ToolMetadata(
                "js_secrets_scanner",
                "JS Bundle Secrets Scanner",
                "SECURITY",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Scans client-side JavaScript bundles to detect leaked API keys, tokens, and credentials.",
                Map.of("jsUrls", List.of(), "maxFiles", 10)
        ));

        register(new ToolMetadata(
                "cors_misconfig_check",
                "CORS Misconfiguration & Origin Probe",
                "SECURITY",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Tests CORS implementation against arbitrary and null origins with credentials.",
                Map.of("customOrigins", List.of())
        ));

        register(new ToolMetadata(
                "subdomain_takeover_check",
                "Subdomain Takeover & Dangling DNS",
                "DNS",
                ExecutionType.DIRECT_TARGET_PROBE,
                "Inspects CNAME records for dangling pointers to unclaimed third-party cloud services.",
                Map.of("subdomains", List.of())
        ));

        // 3. Offline Analytical Tools (2 tools)
        register(new ToolMetadata(
                "security_headers_score",
                "Security Headers Evaluation Score",
                "ANALYSIS",
                ExecutionType.OFFLINE_ANALYSIS,
                "Purely offline analysis tool evaluating headers previously captured by http_headers.",
                Map.of("stepId", "")
        ));

        register(new ToolMetadata(
                "cve_matcher",
                "Technology CVE & Flaw Matcher",
                "ANALYSIS",
                ExecutionType.OFFLINE_ANALYSIS,
                "Correlates detected server and library versions against known CVEs offline.",
                Map.of("stepId", "")
        ));
    }

    private void register(ToolMetadata metadata) {
        metadataMap.put(metadata.id(), metadata);
    }

    public void registerToolBean(OspysinTool tool) {
        if (tool != null && tool.getToolId() != null) {
            toolBeans.put(tool.getToolId(), tool);
        }
    }

    public List<ToolMetadata> getAllTools() {
        return List.copyOf(metadataMap.values());
    }

    public Optional<ToolMetadata> findMetadata(String toolId) {
        if (toolId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(metadataMap.get(toolId));
    }

    public boolean isRegistered(String toolId) {
        return toolId != null && metadataMap.containsKey(toolId);
    }

    public Optional<OspysinTool> getTool(String toolId) {
        if (toolId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(toolBeans.get(toolId));
    }

    public void validateParams(String toolId, Map<String, Object> params) throws ValidationException {
        if (!isRegistered(toolId)) {
            throw new IllegalArgumentException("Unknown tool ID: " + toolId);
        }

        List<InvalidParam> invalidParams = new ArrayList<>();
        Map<String, Object> safeParams = params != null ? params : Map.of();

        // 1. Generic parameter validations based on schema definitions
        if (safeParams.containsKey("customPort") && safeParams.get("customPort") != null) {
            Object val = safeParams.get("customPort");
            int port = parseInteger(val);
            if (port < 1 || port > 65535) {
                invalidParams.add(new InvalidParam("customPort", "customPort must be an integer between 1 and 65535"));
            }
        }

        if (safeParams.containsKey("port") && safeParams.get("port") != null) {
            Object val = safeParams.get("port");
            int port = parseInteger(val);
            if (port < 1 || port > 65535) {
                invalidParams.add(new InvalidParam("port", "port must be an integer between 1 and 65535"));
            }
        }

        if (safeParams.containsKey("followRedirects") && safeParams.get("followRedirects") != null) {
            Object val = safeParams.get("followRedirects");
            if (!(val instanceof Boolean)) {
                invalidParams.add(new InvalidParam("followRedirects", "followRedirects must be a boolean"));
            }
        }

        if (safeParams.containsKey("maxUrls") && safeParams.get("maxUrls") != null) {
            int maxUrls = parseInteger(safeParams.get("maxUrls"));
            if (maxUrls < 1 || maxUrls > 10000) {
                invalidParams.add(new InvalidParam("maxUrls", "maxUrls must be between 1 and 10000"));
            }
        }

        if (safeParams.containsKey("maxLinks") && safeParams.get("maxLinks") != null) {
            int maxLinks = parseInteger(safeParams.get("maxLinks"));
            if (maxLinks < 1 || maxLinks > 5000) {
                invalidParams.add(new InvalidParam("maxLinks", "maxLinks must be between 1 and 5000"));
            }
        }

        if (safeParams.containsKey("maxFiles") && safeParams.get("maxFiles") != null) {
            int maxFiles = parseInteger(safeParams.get("maxFiles"));
            if (maxFiles < 1 || maxFiles > 50) {
                invalidParams.add(new InvalidParam("maxFiles", "maxFiles must be between 1 and 50"));
            }
        }

        if (safeParams.containsKey("referralDepth") && safeParams.get("referralDepth") != null) {
            int depth = parseInteger(safeParams.get("referralDepth"));
            if (depth < 0 || depth > 10) {
                invalidParams.add(new InvalidParam("referralDepth", "referralDepth must be between 0 and 10"));
            }
        }

        // Validate stepId: required and valid UUID on offline analytical tools
        if ("security_headers_score".equals(toolId) || "cve_matcher".equals(toolId)) {
            if (!safeParams.containsKey("stepId") || safeParams.get("stepId") == null || safeParams.get("stepId").toString().trim().isEmpty()) {
                invalidParams.add(new InvalidParam("stepId", "stepId is required and must be a valid UUID"));
            } else {
                try {
                    UUID.fromString(safeParams.get("stepId").toString().trim());
                } catch (IllegalArgumentException e) {
                    invalidParams.add(new InvalidParam("stepId", "stepId must be a valid UUID"));
                }
            }
        } else if (safeParams.containsKey("stepId") && safeParams.get("stepId") != null) {
            String stepStr = safeParams.get("stepId").toString().trim();
            if (!stepStr.isEmpty()) {
                try {
                    UUID.fromString(stepStr);
                } catch (IllegalArgumentException e) {
                    invalidParams.add(new InvalidParam("stepId", "stepId must be a valid UUID"));
                }
            }
        }

        // Validate list parameters
        List<String> listParamNames = List.of("recordTypes", "customPaths", "jsUrls", "customOrigins", "subdomains");
        for (String listParam : listParamNames) {
            if (safeParams.containsKey(listParam) && safeParams.get(listParam) != null) {
                if (!(safeParams.get(listParam) instanceof List<?>)) {
                    invalidParams.add(new InvalidParam(listParam, listParam + " must be a list"));
                }
            }
        }

        if (safeParams.containsKey("stopOnFirstExposed") && safeParams.get("stopOnFirstExposed") != null) {
            Object val = safeParams.get("stopOnFirstExposed");
            if (!(val instanceof Boolean)) {
                invalidParams.add(new InvalidParam("stopOnFirstExposed", "stopOnFirstExposed must be a boolean"));
            }
        }

        // 2. Delegate to tool SPI bean if registered
        OspysinTool tool = toolBeans.get(toolId);
        if (tool != null) {
            try {
                tool.validateParams(safeParams);
            } catch (ValidationException e) {
                for (InvalidParam ip : e.getInvalidParams()) {
                    boolean alreadyPresent = invalidParams.stream()
                            .anyMatch(existing -> existing.name().equals(ip.name()));
                    if (!alreadyPresent) {
                        invalidParams.add(ip);
                    }
                }
            }
        }

        if (!invalidParams.isEmpty()) {
            throw new ValidationException("Tool parameter validation failed for " + toolId, invalidParams);
        }
    }

    private int parseInteger(Object value) {
        if (value == null) {
            return -1;
        }
        if (value instanceof Integer i) {
            return i;
        }
        if (value instanceof Short s) {
            return s.intValue();
        }
        if (value instanceof Byte b) {
            return b.intValue();
        }
        if (value instanceof Long l) {
            if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
                return -1;
            }
            return l.intValue();
        }
        if (value instanceof String str) {
            try {
                long parsed = Long.parseLong(str.trim());
                if (parsed < Integer.MIN_VALUE || parsed > Integer.MAX_VALUE) {
                    return -1;
                }
                return (int) parsed;
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        // Reject floating-point (Float, Double) or other object types
        return -1;
    }
}
