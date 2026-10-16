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
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.BiPredicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool #11: Exposed Sensitive Files & Endpoints probe.
 * Probes target server directly for curated sensitive files, backups, VCS metadata,
 * and Spring Boot Actuators using content/magic-byte signature verification.
 */
@Component
public class SensitiveFilesCheckTool implements OspysinTool {

    private static final Logger log = LoggerFactory.getLogger(SensitiveFilesCheckTool.class);

    public static final String TOOL_ID = "sensitive_files_check";
    public static final long WIRE_CAP_BYTES = 64 * 1024L; // 64 KB
    public static final long DECOMPRESSED_CAP_BYTES = 64 * 1024L; // 64 KB
    public static final int READ_TIMEOUT_MS = 15_000; // 15s

    private static final Pattern ENV_KEY_VALUE_PATTERN = Pattern.compile("(?m)^[A-Za-z_][A-Za-z0-9_]*\\s*=.*");
    private static final Pattern GIT_COMMIT_PATTERN = Pattern.compile("^[0-9a-fA-F]{40}(\\r?\\n)?$");

    private static final Pattern REDACT_KEY_VALUE_PATTERN = Pattern.compile(
            "(?im)^(\\s*[A-Za-z0-9_.\\-]*?(?:password|passwd|pwd|secret|token|api_?key|private_?key|credentials|auth)[A-Za-z0-9_.\\-]*\\s*[:=]\\s*)([^\\r\\n]+)$"
    );

    private static final Pattern REDACT_JSON_PATTERN = Pattern.compile(
            "\"((?:password|secret|token|apiKey|privateKey)[^\"]*)\"\\s*:\\s*\"[^\"]*\""
    );

    private record ProbeDefinition(
            String path,
            String category,
            String severity,
            BiPredicate<PinnedHttpResponse, String> matcher
    ) {}

    private static final List<ProbeDefinition> BUILT_IN_PROBES = initializeBuiltInProbes();

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;
    private final HostRateLimiter hostRateLimiter;

    @Autowired
    public SensitiveFilesCheckTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine, HostRateLimiter hostRateLimiter) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.hostRateLimiter = hostRateLimiter;
    }

    public SensitiveFilesCheckTool(PinnedHttpClient pinnedHttpClient, PolicyEngine policyEngine) {
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

        if (params.containsKey("customPaths")) {
            Object val = params.get("customPaths");
            if (val == null) {
                errors.add(new InvalidParam("customPaths", "customPaths must not be null"));
            } else if (!(val instanceof List<?> list)) {
                errors.add(new InvalidParam("customPaths", "customPaths must be a list"));
            } else {
                if (list.size() > 20) {
                    errors.add(new InvalidParam("customPaths", "customPaths list must contain at most 20 paths"));
                }
                for (int i = 0; i < list.size(); i++) {
                    Object item = list.get(i);
                    if (!(item instanceof String s) || s.isBlank() || !s.startsWith("/") || s.startsWith("//")
                            || s.contains("..") || s.contains("\\") || s.contains("\r") || s.contains("\n")
                            || s.contains("://") || s.length() > 255) {
                        errors.add(new InvalidParam("customPaths",
                                "Path at index " + i + " must start with '/', not start with '//', not contain '..', '\\', CR, LF, or '://', and length <= 255"));
                        break;
                    }
                }
            }
        }

        if (params.containsKey("stopOnFirstExposed")) {
            Object val = params.get("stopOnFirstExposed");
            if (val == null) {
                errors.add(new InvalidParam("stopOnFirstExposed", "stopOnFirstExposed must not be null"));
            } else if (!(val instanceof Boolean)) {
                errors.add(new InvalidParam("stopOnFirstExposed", "stopOnFirstExposed must be a boolean"));
            }
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Parameter validation failed for sensitive_files_check", errors);
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        URI baseUri = URI.create(context.targetUrl().trim());

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            PolicyDecision decision = policyEngine.evaluate(baseUri, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for sensitive_files_check: " + decision.reason(),
                        List.of(new InvalidParam("targetUrl", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        Map<String, Object> inputParams = context.inputParams();
        boolean stopOnFirstExposed = Boolean.TRUE.equals(inputParams.get("stopOnFirstExposed"));

        @SuppressWarnings("unchecked")
        List<String> customPathsList = (List<String>) inputParams.getOrDefault("customPaths", Collections.emptyList());

        // Prepare combined probes preserving order
        Map<String, ProbeDefinition> probeMap = new LinkedHashMap<>();
        for (ProbeDefinition probe : BUILT_IN_PROBES) {
            probeMap.put(probe.path(), probe);
        }

        if (customPathsList != null) {
            for (String path : customPathsList) {
                if (path != null && !path.isBlank() && !probeMap.containsKey(path)) {
                    probeMap.put(path, new ProbeDefinition(
                            path,
                            "Custom Paths",
                            "MEDIUM",
                            (resp, body) -> !isHtml(body) && !body.isBlank()
                    ));
                }
            }
        }

        List<Map<String, Object>> exposedFiles = new ArrayList<>();
        List<ObservationDraft> observations = new ArrayList<>();
        StringBuilder rawTrace = new StringBuilder();
        int totalChecked = 0;

        String targetHost = baseUri.getHost() != null ? baseUri.getHost() : "localhost";
        for (Map.Entry<String, ProbeDefinition> entry : probeMap.entrySet()) {
            String path = entry.getKey();
            ProbeDefinition def = entry.getValue();
            totalChecked++;

            if (hostRateLimiter != null) {
                hostRateLimiter.acquire(targetHost);
            }

            URI probeUri = baseUri.resolve(path);

            try {
                PinnedHttpResponse response = pinnedHttpClient.executeSingle(
                        probeUri,
                        pinnedIp,
                        WIRE_CAP_BYTES,
                        DECOMPRESSED_CAP_BYTES,
                        READ_TIMEOUT_MS
                );

                int statusCode = response.statusCode();
                String bodyText = new String(response.bodyBytes(), StandardCharsets.UTF_8);

                rawTrace.append("CHECK ").append(path).append(" -> HTTP ").append(statusCode).append("\n");

                if (statusCode == 200 && def.matcher().test(response, bodyText)) {
                    boolean isBuiltIn = BUILT_IN_PROBES.stream().anyMatch(p -> p.path().equals(path));
                    String confidence = isBuiltIn ? "HIGH" : "MEDIUM";
                    String severity = def.severity();

                    String contentType = getHeader(response.headers(), "content-type");
                    if (contentType == null || contentType.isBlank()) {
                        contentType = "application/octet-stream";
                    }

                    String snippet = formatSnippet(path, response.bodyBytes(), bodyText);

                    Map<String, Object> exposedEntry = new LinkedHashMap<>();
                    exposedEntry.put("path", path);
                    exposedEntry.put("statusCode", 200);
                    exposedEntry.put("contentType", contentType);
                    exposedEntry.put("confidence", confidence);
                    exposedEntry.put("snippet", snippet);
                    exposedEntry.put("severity", severity);
                    exposedFiles.add(exposedEntry);

                    SeverityHeuristic severityHeuristic = toSeverityHeuristic(severity);
                    observations.add(new ObservationDraft(
                            "SENSITIVE_FILE_EXPOSED",
                            "Exposed sensitive file or endpoint at " + path + " (HTTP 200, severity " + severity + ")",
                            severityHeuristic
                    ));

                    if (stopOnFirstExposed) {
                        rawTrace.append("Stopped probe on first exposed file: ").append(path).append("\n");
                        break;
                    }
                }
            } catch (IOException e) {
                log.debug("I/O error during sensitive file check for {}: {}", path, e.getMessage());
                rawTrace.append("CHECK ").append(path).append(" -> ERROR: ").append(e.getMessage()).append("\n");
            }
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("totalChecked", totalChecked);
        parsedData.put("exposedCount", exposedFiles.size());
        parsedData.put("exposedFiles", exposedFiles);

        String truncatedRaw = Utf8StringUtils.truncateUtf8(rawTrace.toString(), Utf8StringUtils.MAX_RAW_OUTPUT_BYTES);

        return new ToolExecutionOutcome(
                truncatedRaw,
                parsedData,
                null,
                false,
                observations
        );
    }

    private static String formatSnippet(String path, byte[] rawBytes, String bodyText) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".zip") || lower.endsWith(".tar.gz") || lower.endsWith(".gz")
                || lower.endsWith("heapdump") || lower.endsWith(".ds_store")) {
            return "[Binary payload: " + rawBytes.length + " bytes]";
        }

        String redacted = redactCredentials(bodyText);
        if (redacted.length() > 300) {
            return redacted.substring(0, 300);
        }
        return redacted;
    }

    private static String redactCredentials(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String redacted = REDACT_KEY_VALUE_PATTERN.matcher(text).replaceAll("$1***");
        redacted = REDACT_JSON_PATTERN.matcher(redacted).replaceAll("\"$1\": \"***\"");
        return redacted;
    }

    private static boolean isHtml(String bodyText) {
        if (bodyText == null || bodyText.isBlank()) {
            return false;
        }
        String lower = bodyText.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("<!doctype html") || lower.startsWith("<html") || lower.startsWith("<head") || lower.startsWith("<body");
    }

    private static boolean containsAny(String text, String... needles) {
        if (text == null || needles == null) {
            return false;
        }
        for (String needle : needles) {
            if (text.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsBytes(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null || haystack.length < needle.length) {
            return false;
        }
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private static String getHeader(Map<String, List<String>> headers, String name) {
        if (headers == null) return null;
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        if (values != null && !values.isEmpty()) {
            return values.get(0);
        }
        return null;
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

    private static List<ProbeDefinition> initializeBuiltInProbes() {
        List<ProbeDefinition> list = new ArrayList<>();

        // 1. Environment & Configs
        list.add(new ProbeDefinition("/.env", "Environment & Configs", "CRITICAL",
                (resp, body) -> !isHtml(body) && !body.trim().startsWith("<") && ENV_KEY_VALUE_PATTERN.matcher(body).find()));
        list.add(new ProbeDefinition("/.env.local", "Environment & Configs", "CRITICAL",
                (resp, body) -> !isHtml(body) && !body.trim().startsWith("<") && ENV_KEY_VALUE_PATTERN.matcher(body).find()));
        list.add(new ProbeDefinition("/.env.production", "Environment & Configs", "CRITICAL",
                (resp, body) -> !isHtml(body) && !body.trim().startsWith("<") && ENV_KEY_VALUE_PATTERN.matcher(body).find()));
        list.add(new ProbeDefinition("/docker-compose.yml", "Environment & Configs", "HIGH",
                (resp, body) -> !isHtml(body) && (body.contains("services:") || body.contains("version:"))));
        list.add(new ProbeDefinition("/config.json", "Environment & Configs", "HIGH",
                (resp, body) -> body.trim().startsWith("{") && body.contains(":")));
        list.add(new ProbeDefinition("/web.config", "Environment & Configs", "HIGH",
                (resp, body) -> body.contains("<configuration") || body.contains("<system.webServer")));

        // 2. Version Control
        list.add(new ProbeDefinition("/.git/HEAD", "Version Control", "HIGH",
                (resp, body) -> body.startsWith("ref: refs/") || GIT_COMMIT_PATTERN.matcher(body.trim()).matches()));
        list.add(new ProbeDefinition("/.git/config", "Version Control", "CRITICAL",
                (resp, body) -> body.contains("[core]") || body.contains("[remote")));
        list.add(new ProbeDefinition("/.gitignore", "Version Control", "LOW",
                (resp, body) -> !isHtml(body) && containsAny(body, "node_modules", ".env", "target", "dist", "*.log", "build", "#")));
        list.add(new ProbeDefinition("/.svn/entries", "Version Control", "HIGH",
                (resp, body) -> body.contains("dir") || body.contains("svn:") || body.contains("<wc-entries")));

        // 3. Spring Boot Actuators
        list.add(new ProbeDefinition("/actuator", "Spring Boot Actuators", "MEDIUM",
                (resp, body) -> body.trim().startsWith("{") && body.contains("\"_links\"")));
        list.add(new ProbeDefinition("/actuator/env", "Spring Boot Actuators", "CRITICAL",
                (resp, body) -> body.trim().startsWith("{") && (body.contains("\"propertySources\"") || body.contains("\"activeProfiles\""))));
        list.add(new ProbeDefinition("/actuator/health", "Spring Boot Actuators", "LOW",
                (resp, body) -> body.trim().startsWith("{") && body.contains("\"status\"")));
        list.add(new ProbeDefinition("/actuator/heapdump", "Spring Boot Actuators", "CRITICAL",
                (resp, body) -> resp.bodyBytes().length >= 4 && !isHtml(body) && (
                        (resp.bodyBytes()[0] == (byte) 0x1f && resp.bodyBytes()[1] == (byte) 0x8b) || body.contains("JAVA PROFILE"))));
        list.add(new ProbeDefinition("/actuator/beans", "Spring Boot Actuators", "HIGH",
                (resp, body) -> body.trim().startsWith("{") && (body.contains("\"contexts\"") || body.contains("\"beans\""))));

        // 4. Backups & Dumps
        list.add(new ProbeDefinition("/backup.sql", "Backups & Dumps", "CRITICAL",
                (resp, body) -> containsAny(body, "CREATE TABLE", "INSERT INTO", "PostgreSQL database dump", "MySQL dump")));
        list.add(new ProbeDefinition("/dump.sql", "Backups & Dumps", "CRITICAL",
                (resp, body) -> containsAny(body, "CREATE TABLE", "INSERT INTO", "PostgreSQL database dump", "MySQL dump")));
        list.add(new ProbeDefinition("/database.sql", "Backups & Dumps", "CRITICAL",
                (resp, body) -> containsAny(body, "CREATE TABLE", "INSERT INTO", "PostgreSQL database dump", "MySQL dump")));
        list.add(new ProbeDefinition("/backup.zip", "Backups & Dumps", "CRITICAL",
                (resp, body) -> resp.bodyBytes().length >= 4
                        && resp.bodyBytes()[0] == 0x50 && resp.bodyBytes()[1] == 0x4B
                        && resp.bodyBytes()[2] == 0x03 && resp.bodyBytes()[3] == 0x04));
        list.add(new ProbeDefinition("/site.tar.gz", "Backups & Dumps", "CRITICAL",
                (resp, body) -> resp.bodyBytes().length >= 2
                        && resp.bodyBytes()[0] == (byte) 0x1f && resp.bodyBytes()[1] == (byte) 0x8b && !isHtml(body)));
        list.add(new ProbeDefinition("/wp-config.php.bak", "Backups & Dumps", "CRITICAL",
                (resp, body) -> containsAny(body, "DB_NAME", "DB_PASSWORD", "table_prefix", "<?php")));

        // 5. IDE & Editors
        list.add(new ProbeDefinition("/.vscode/sftp.json", "IDE & Editors", "CRITICAL",
                (resp, body) -> body.trim().startsWith("{") && containsAny(body, "\"host\"", "\"username\"", "\"protocol\"", "\"remotePath\"")));
        list.add(new ProbeDefinition("/.idea/workspace.xml", "IDE & Editors", "MEDIUM",
                (resp, body) -> body.contains("<project") || body.contains("<component")));
        list.add(new ProbeDefinition("/.DS_Store", "IDE & Editors", "LOW",
                (resp, body) -> containsBytes(resp.bodyBytes(), "Bud1".getBytes(StandardCharsets.US_ASCII))));

        // 6. Documentation & Debug
        list.add(new ProbeDefinition("/swagger-ui.html", "Documentation & Debug", "LOW",
                (resp, body) -> body.contains("swagger-ui") || body.contains("Swagger UI")));
        list.add(new ProbeDefinition("/v2/api-docs", "Documentation & Debug", "LOW",
                (resp, body) -> body.trim().startsWith("{") && (body.contains("\"swagger\"") || body.contains("\"openapi\""))));
        list.add(new ProbeDefinition("/v3/api-docs", "Documentation & Debug", "LOW",
                (resp, body) -> body.trim().startsWith("{") && (body.contains("\"swagger\"") || body.contains("\"openapi\""))));
        list.add(new ProbeDefinition("/phpinfo.php", "Documentation & Debug", "HIGH",
                (resp, body) -> body.contains("phpinfo()") || body.contains("PHP Version")));
        list.add(new ProbeDefinition("/server-status", "Documentation & Debug", "MEDIUM",
                (resp, body) -> body.contains("Apache Server Status") || body.contains("Server Version:")));

        return Collections.unmodifiableList(list);
    }
}
