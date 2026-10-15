package com.ospysin.tools.analysis;

import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.ResourceNotFoundException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.OspysinTool;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool #14: Technology CVE & Flaw Matcher offline analytical tool (cve_matcher).
 * Correlates web server, framework, and library versions discovered by tech_detect
 * against a curated local database of known CVEs using semantic version range comparison.
 * Executes purely offline with zero network I/O and enforces strict BOLA session isolation.
 */
@Component
public class CveMatcherTool implements OspysinTool {

    public static final String TOOL_ID = "cve_matcher";

    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;
    private final List<CveCatalogEntry> catalog;

    @Autowired
    public CveMatcherTool(ToolExecutionRepository toolExecutionRepository,
                          ToolResultRepository toolResultRepository) {
        this.toolExecutionRepository = Objects.requireNonNull(toolExecutionRepository, "toolExecutionRepository must not be null");
        this.toolResultRepository = Objects.requireNonNull(toolResultRepository, "toolResultRepository must not be null");
        this.catalog = initCuratedCatalog();
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        if (params == null || !params.containsKey("stepId") || params.get("stepId") == null
                || params.get("stepId").toString().trim().isEmpty()) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId is required and must be a valid UUID"))
            );
        }

        try {
            UUID.fromString(params.get("stepId").toString().trim());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId must be a valid UUID"))
            );
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        Object stepIdVal = context.inputParams().get("stepId");
        if (stepIdVal == null || stepIdVal.toString().trim().isEmpty()) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId is required and must be a valid UUID"))
            );
        }

        UUID stepUuid;
        try {
            stepUuid = UUID.fromString(stepIdVal.toString().trim());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId must be a valid UUID"))
            );
        }

        // 1. Fetch referenced step
        ToolExecution execution = toolExecutionRepository.findById(stepUuid)
                .orElseThrow(() -> new ResourceNotFoundException("Step not found: " + stepUuid));

        // 2. Strict BOLA Session Ownership Guard
        if (!execution.getSession().getId().equals(context.sessionId())) {
            throw new ResourceNotFoundException("Step not found: " + stepUuid);
        }

        // 3. Prerequisite Tool & Completion Status Verification
        if (execution.getStatus() != ExecutionStatus.COMPLETED || !"tech_detect".equals(execution.getToolId())) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "Referenced step must be a completed tech_detect execution"))
            );
        }

        // 4. Fetch ToolResult
        ToolResult techDetectResult = toolResultRepository.findByExecutionId(stepUuid)
                .orElseThrow(() -> new ResourceNotFoundException("Tool result not found for step: " + stepUuid));

        // 5. Extract Detected Technologies
        List<Map<String, Object>> technologies = extractTechnologies(techDetectResult.getParsedData());

        // 6. Match Against Curated Offline CVE Catalog
        List<Map<String, Object>> matchedVulnerabilities = new ArrayList<>();
        List<ObservationDraft> observations = new ArrayList<>();

        for (Map<String, Object> tech : technologies) {
            String name = tech.get("name") != null ? tech.get("name").toString() : "";
            String version = tech.get("version") != null ? tech.get("version").toString() : null;

            if (version == null || version.isBlank()) {
                continue; // Cannot correlate CVEs without a disclosed version
            }

            for (CveCatalogEntry entry : catalog) {
                if (entry.matches(name, version)) {
                    Map<String, Object> vulnMap = new LinkedHashMap<>();
                    vulnMap.put("component", entry.component());
                    vulnMap.put("detectedVersion", version);
                    vulnMap.put("cveId", entry.cveId());
                    vulnMap.put("cvss", entry.cvss());
                    vulnMap.put("severity", entry.severity());
                    vulnMap.put("title", entry.title());
                    vulnMap.put("hasPublicExploit", entry.hasPublicExploit());
                    vulnMap.put("description", entry.description());
                    vulnMap.put("remediation", entry.remediation());
                    matchedVulnerabilities.add(vulnMap);

                    SeverityHeuristic heuristic = toHeuristic(entry.severity());
                    observations.add(new ObservationDraft(
                            "CVE_MATCH",
                            entry.cveId() + " (" + entry.component() + " " + version + ", CVSS " + entry.cvss() + "): " + entry.title(),
                            heuristic
                    ));
                }
            }
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("matchedCount", matchedVulnerabilities.size());
        parsedData.put("vulnerabilities", matchedVulnerabilities);
        parsedData.put("evaluatedStepId", stepUuid.toString());

        String rawOutput = buildRawOutput(matchedVulnerabilities);

        return new ToolExecutionOutcome(
                rawOutput,
                parsedData,
                null,
                false,
                observations
        );
    }

    private List<Map<String, Object>> extractTechnologies(Map<String, Object> parsedData) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (parsedData != null && parsedData.get("technologies") instanceof List<?> rawList) {
            for (Object item : rawList) {
                if (item instanceof Map<?, ?> map) {
                    Map<String, Object> typed = new LinkedHashMap<>();
                    for (Map.Entry<?, ?> e : map.entrySet()) {
                        if (e.getKey() != null) {
                            typed.put(e.getKey().toString(), e.getValue());
                        }
                    }
                    list.add(typed);
                }
            }
        }
        return list;
    }

    private SeverityHeuristic toHeuristic(String severity) {
        if ("CRITICAL".equalsIgnoreCase(severity) || "HIGH".equalsIgnoreCase(severity)) {
            return SeverityHeuristic.HIGH;
        }
        if ("MEDIUM".equalsIgnoreCase(severity)) {
            return SeverityHeuristic.MEDIUM;
        }
        return SeverityHeuristic.LOW;
    }

    private String buildRawOutput(List<Map<String, Object>> vulnerabilities) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Offline Technology CVE Correlation Report ===\n");
        sb.append("Total Vulnerabilities Matched: ").append(vulnerabilities.size()).append("\n\n");

        if (vulnerabilities.isEmpty()) {
            sb.append("No known critical or high severity vulnerabilities found in local database for the identified versions.\n");
        } else {
            for (int i = 0; i < vulnerabilities.size(); i++) {
                Map<String, Object> v = vulnerabilities.get(i);
                sb.append(i + 1).append(". [").append(v.get("cveId")).append("] ")
                        .append(v.get("component")).append(" ").append(v.get("detectedVersion"))
                        .append(" — ").append(v.get("title")).append("\n");
                sb.append("   Severity: ").append(v.get("severity"))
                        .append(" (CVSS ").append(v.get("cvss")).append(")")
                        .append(" | Exploit Available: ").append(v.get("hasPublicExploit")).append("\n");
                sb.append("   Description: ").append(v.get("description")).append("\n");
                sb.append("   Remediation: ").append(v.get("remediation")).append("\n\n");
            }
        }

        return sb.toString();
    }

    private List<CveCatalogEntry> initCuratedCatalog() {
        List<CveCatalogEntry> entries = new ArrayList<>();

        // 1. Apache HTTP Server
        entries.add(new CveCatalogEntry(
                "Apache HTTP Server",
                null, null, "2.4.49",
                "CVE-2021-41773", 7.5, "HIGH", true,
                "Path Traversal and File Disclosure",
                "A flaw in path normalization in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the document root and execute arbitrary code if CGI is enabled.",
                "Upgrade Apache HTTP Server to version 2.4.51 or higher immediately."
        ));
        entries.add(new CveCatalogEntry(
                "Apache HTTP Server",
                "2.4.49", "2.4.50", null,
                "CVE-2021-42013", 9.8, "CRITICAL", true,
                "Path Traversal and Remote Code Execution",
                "An incomplete fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 allows path traversal and remote code execution.",
                "Upgrade Apache HTTP Server to version 2.4.51 or higher immediately."
        ));
        entries.add(new CveCatalogEntry(
                "Apache HTTP Server",
                "2.4.0", "2.4.55", null,
                "CVE-2023-25690", 9.8, "CRITICAL", true,
                "HTTP Request Smuggling via mod_proxy",
                "HTTP request smuggling vulnerability in Apache HTTP Server 2.4.0 through 2.4.55 allows a remote attacker to bypass access controls or poison the proxy cache.",
                "Upgrade Apache HTTP Server to version 2.4.56 or higher."
        ));

        // 2. Nginx
        entries.add(new CveCatalogEntry(
                "Nginx",
                "0.6.18", "1.20.0", null,
                "CVE-2021-23017", 7.7, "HIGH", false,
                "1-Byte Memory Overwrite in DNS Resolver",
                "A 1-byte memory overwrite in Nginx DNS resolver enables remote attackers to crash workers or achieve code execution.",
                "Upgrade Nginx to version 1.20.1 / 1.21.0 or higher."
        ));
        entries.add(new CveCatalogEntry(
                "Nginx",
                "1.1.3", "1.23.1", null,
                "CVE-2022-41741", 7.8, "HIGH", false,
                "Memory Corruption in ngx_http_mp4_module",
                "Memory corruption in the ngx_http_mp4_module enables an attacker to cause worker process crash or memory disclosure.",
                "Upgrade Nginx to version 1.22.1 / 1.23.2 or higher."
        ));

        // 3. PHP
        entries.add(new CveCatalogEntry(
                "PHP",
                "8.0.0", "8.3.7", null,
                "CVE-2024-4577", 9.8, "CRITICAL", true,
                "PHP-CGI Argument Injection Remote Code Execution",
                "Best-fit encoding conversion in Windows PHP-CGI allows remote attackers to inject command arguments and execute arbitrary code.",
                "Upgrade PHP to 8.1.29, 8.2.20, or 8.3.8 or higher."
        ));

        // 4. Spring Boot
        entries.add(new CveCatalogEntry(
                "Spring Boot",
                "2.0.0", "2.6.5", null,
                "CVE-2022-22965", 9.8, "CRITICAL", true,
                "Spring4Shell Remote Code Execution via Data Binding",
                "Remote code execution in Spring Framework via data binding when running on JDK 9+ with Apache Tomcat.",
                "Upgrade Spring Boot to 2.6.6+ or 3.x."
        ));
        entries.add(new CveCatalogEntry(
                "Spring Boot",
                "3.0.0", "3.0.6", null,
                "CVE-2023-20883", 7.5, "HIGH", false,
                "Spring Boot Welcome Page DoS Vulnerability",
                "Spring Boot applications providing welcome pages may be vulnerable to denial of service attacks.",
                "Upgrade Spring Boot to 3.0.7 or higher."
        ));

        // 5. WordPress
        entries.add(new CveCatalogEntry(
                "WordPress",
                "0.1", "6.4.2", null,
                "CVE-2023-2982", 7.5, "HIGH", false,
                "Outdated WordPress Core Exposure",
                "Outdated WordPress core exposing known security flaws and unauthenticated attack vectors.",
                "Upgrade WordPress core to the latest stable release."
        ));

        // 6. Drupal
        entries.add(new CveCatalogEntry(
                "Drupal",
                "7.0", "8.5.0", null,
                "CVE-2018-7600", 9.8, "CRITICAL", true,
                "Drupalgeddon2 Remote Code Execution",
                "Remote code execution vulnerability in Drupal 7.x and 8.x form rendering architecture.",
                "Upgrade Drupal to version 8.5.1 / 9.x / 10.x or higher."
        ));

        // 7. Joomla
        entries.add(new CveCatalogEntry(
                "Joomla",
                "4.0.0", "4.2.7", null,
                "CVE-2023-23752", 5.3, "MEDIUM", true,
                "Improper Access Check Information Disclosure",
                "Improper access check within Joomla Web Services endpoints leads to unauthorized disclosure of database credentials.",
                "Upgrade Joomla to version 4.2.8 or higher."
        ));

        // 8. jQuery
        entries.add(new CveCatalogEntry(
                "jQuery",
                "1.2.0", "3.4.1", null,
                "CVE-2020-11022", 6.1, "MEDIUM", true,
                "Cross-Site Scripting (XSS) in jQuery.htmlPrefilter",
                "Passing HTML containing elements from untrusted sources to jQuery manipulation methods can result in cross-site scripting.",
                "Upgrade jQuery to version 3.5.0 or higher."
        ));

        // 9. AngularJS
        entries.add(new CveCatalogEntry(
                "AngularJS",
                "1.0.0", "1.8.3", null,
                "CVE-2022-25869", 6.1, "MEDIUM", false,
                "End-of-Life AngularJS 1.x XSS Exposure",
                "AngularJS 1.x reached end of life and contains unpatched Universal XSS and prototype pollution vectors.",
                "Migrate from EOL AngularJS 1.x to modern Angular or Vue."
        ));

        // 10. Bootstrap
        entries.add(new CveCatalogEntry(
                "Bootstrap",
                "3.0.0", "4.3.0", null,
                "CVE-2019-8331", 6.1, "MEDIUM", false,
                "XSS Vulnerability in Bootstrap Tooltip/Popover data-template",
                "XSS in the tooltip and popover plugins of Bootstrap via the data-template attribute.",
                "Upgrade Bootstrap to version 4.3.1 / 5.x or higher."
        ));

        return Collections.unmodifiableList(entries);
    }

    public static int compareVersions(String v1, String v2) {
        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;

        String cleanV1 = v1.trim().replaceAll("^[vV]", "");
        String cleanV2 = v2.trim().replaceAll("^[vV]", "");

        String[] parts1 = cleanV1.split("[.-]");
        String[] parts2 = cleanV2.split("[.-]");

        int maxLen = Math.max(parts1.length, parts2.length);
        for (int i = 0; i < maxLen; i++) {
            int p1 = (i < parts1.length) ? parseNumericPrefix(parts1[i]) : 0;
            int p2 = (i < parts2.length) ? parseNumericPrefix(parts2[i]) : 0;
            if (p1 != p2) {
                return Integer.compare(p1, p2);
            }
        }
        return 0;
    }

    private static int parseNumericPrefix(String s) {
        if (s == null || s.isBlank()) {
            return 0;
        }
        Matcher m = Pattern.compile("^\\d+").matcher(s);
        if (m.find()) {
            try {
                return Integer.parseInt(m.group());
            } catch (NumberFormatException ignored) {}
        }
        return 0;
    }

    private static String normalizeComponentName(String name) {
        if (name == null) return "";
        String lower = name.toLowerCase(Locale.ROOT).trim();
        if (lower.contains("apache")) return "apache http server";
        if (lower.contains("nginx")) return "nginx";
        if (lower.equals("php")) return "php";
        if (lower.contains("spring")) return "spring boot";
        if (lower.contains("wordpress")) return "wordpress";
        if (lower.contains("drupal")) return "drupal";
        if (lower.contains("joomla")) return "joomla";
        if (lower.contains("jquery")) return "jquery";
        if (lower.contains("angularjs")) return "angularjs";
        if (lower.equals("angular") || lower.startsWith("angular")) return "angularjs";
        if (lower.contains("bootstrap")) return "bootstrap";
        return lower;
    }

    private record CveCatalogEntry(
            String component,
            String minVersionInclusive,
            String maxVersionInclusive,
            String exactVersion,
            String cveId,
            double cvss,
            String severity,
            boolean hasPublicExploit,
            String title,
            String description,
            String remediation
    ) {
        public boolean matches(String comp, String version) {
            if (version == null || version.isBlank() || comp == null) {
                return false;
            }

            String c1 = normalizeComponentName(this.component);
            String c2 = normalizeComponentName(comp);
            if (!c1.equals(c2)) {
                return false;
            }

            if (exactVersion != null) {
                return compareVersions(version, exactVersion) == 0;
            }

            if (minVersionInclusive != null && compareVersions(version, minVersionInclusive) < 0) {
                return false;
            }

            if (maxVersionInclusive != null && compareVersions(version, maxVersionInclusive) > 0) {
                return false;
            }

            return true;
        }
    }
}
