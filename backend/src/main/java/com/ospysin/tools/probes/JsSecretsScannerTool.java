package com.ospysin.tools.probes;

import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.HostRateLimiter;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.policy.io.AggregatePayloadBudget;
import com.ospysin.policy.io.PayloadLimitExceededException;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.shared.util.Utf8StringUtils;
import com.ospysin.tools.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool #12: JS Bundle Secrets Scanner direct probe.
 * Downloads client-side JavaScript bundles and scans for leaked API keys, tokens,
 * private keys, and high-entropy credentials, enforcing 4-tier payload boundaries.
 */
@Component
public class JsSecretsScannerTool implements OspysinTool {

    private static final Logger log = LoggerFactory.getLogger(JsSecretsScannerTool.class);

    public static final String TOOL_ID = "js_secrets_scanner";
    public static final long WIRE_CAP_PER_FILE = 1024 * 1024L; // 1 MB
    public static final long DECOMPRESSED_CAP_PER_FILE = 2 * 1024 * 1024L; // 2 MB
    public static final long AGGREGATE_CAP = 5 * 1024 * 1024L; // 5 MB
    public static final int READ_TIMEOUT_MS = 20_000; // 20s
    public static final int DEFAULT_MAX_FILES = 10;
    public static final int MAX_ALLOWED_FILES = 50;

    // Secret Patterns
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile(
            "(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}(?![A-Z0-9])"
    );
    private static final Pattern GCP_KEY_PATTERN = Pattern.compile(
            "(?<![0-9A-Za-z\\-_])AIza[0-9A-Za-z\\-_]{35}(?![0-9A-Za-z\\-_])"
    );
    private static final Pattern STRIPE_KEY_PATTERN = Pattern.compile(
            "(?<![0-9a-zA-Z])(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}"
    );
    private static final Pattern GITHUB_PAT_PATTERN = Pattern.compile(
            "(?<![0-9a-zA-Z])(?:(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,}|github_pat_[0-9a-zA-Z_]{82})"
    );
    private static final Pattern SLACK_TOKEN_PATTERN = Pattern.compile(
            "(?<![0-9a-zA-Z])(?:xox[baprs]-[0-9a-zA-Z\\-]{10,48}|https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)"
    );
    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    );
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
    );
    private static final Pattern ENTROPY_ASSIGNMENT_PATTERN = Pattern.compile(
            "(?i)(?:password|passwd|secret|api_?key|access_?token|auth_?token|client_?secret)\\s*[:=]\\s*[\"']([^\"'\\r\\n\\s]{16,128})[\"']"
    );

    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;
    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;
    private final HostRateLimiter hostRateLimiter;

    @Autowired
    public JsSecretsScannerTool(PinnedHttpClient pinnedHttpClient,
                                PolicyEngine policyEngine,
                                ToolExecutionRepository toolExecutionRepository,
                                ToolResultRepository toolResultRepository,
                                HostRateLimiter hostRateLimiter) {
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.toolExecutionRepository = Objects.requireNonNull(toolExecutionRepository, "toolExecutionRepository must not be null");
        this.toolResultRepository = Objects.requireNonNull(toolResultRepository, "toolResultRepository must not be null");
        this.hostRateLimiter = hostRateLimiter;
    }

    public JsSecretsScannerTool(PinnedHttpClient pinnedHttpClient,
                                PolicyEngine policyEngine,
                                ToolExecutionRepository toolExecutionRepository,
                                ToolResultRepository toolResultRepository) {
        this(pinnedHttpClient, policyEngine, toolExecutionRepository, toolResultRepository, null);
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

        if (params.containsKey("jsUrls")) {
            Object val = params.get("jsUrls");
            if (val == null) {
                errors.add(new InvalidParam("jsUrls", "jsUrls must not be null"));
            } else if (!(val instanceof List<?> list)) {
                errors.add(new InvalidParam("jsUrls", "jsUrls must be a list"));
            } else {
                if (list.size() > 50) {
                    errors.add(new InvalidParam("jsUrls", "jsUrls must contain at most 50 URLs"));
                }
                for (int i = 0; i < list.size(); i++) {
                    Object item = list.get(i);
                    if (!(item instanceof String s) || s.isBlank() || s.length() > 500
                            || s.contains("\r") || s.contains("\n")) {
                        errors.add(new InvalidParam("jsUrls", "URL at index " + i + " must be a non-blank string <= 500 chars without CRLF"));
                        break;
                    }
                    String lower = s.trim().toLowerCase(Locale.ROOT);
                    if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
                        errors.add(new InvalidParam("jsUrls", "URL at index " + i + " must start with http:// or https://"));
                        break;
                    }
                    try {
                        URI uri = URI.create(s.trim());
                        if (uri.getHost() == null || uri.getHost().isBlank()) {
                            errors.add(new InvalidParam("jsUrls", "URL at index " + i + " must have a valid host"));
                            break;
                        }
                    } catch (Exception ex) {
                        errors.add(new InvalidParam("jsUrls", "URL at index " + i + " is malformed: " + ex.getMessage()));
                        break;
                    }
                }
            }
        }

        if (params.containsKey("maxFiles")) {
            Object val = params.get("maxFiles");
            if (val == null) {
                errors.add(new InvalidParam("maxFiles", "maxFiles must not be null"));
            } else {
                int maxFiles = parseInteger(val);
                if (maxFiles < 1 || maxFiles > MAX_ALLOWED_FILES) {
                    errors.add(new InvalidParam("maxFiles", "maxFiles must be between 1 and " + MAX_ALLOWED_FILES));
                }
            }
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Parameter validation failed for js_secrets_scanner", errors);
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        Map<String, Object> inputParams = context.inputParams();
        int maxFiles = DEFAULT_MAX_FILES;
        if (inputParams.containsKey("maxFiles") && inputParams.get("maxFiles") != null) {
            int parsed = parseInteger(inputParams.get("maxFiles"));
            if (parsed >= 1 && parsed <= MAX_ALLOWED_FILES) {
                maxFiles = parsed;
            }
        }

        AggregatePayloadBudget aggregateBudget = new AggregatePayloadBudget(AGGREGATE_CAP);

        // Resolve JS URLs
        List<String> targetJsUrls = resolveJsUrls(context, maxFiles, aggregateBudget);

        List<Map<String, Object>> findings = new ArrayList<>();
        List<ObservationDraft> observations = new ArrayList<>();
        StringBuilder rawTrace = new StringBuilder();
        int filesScanned = 0;

        for (String jsUrl : targetJsUrls) {
            if (filesScanned >= maxFiles) {
                break;
            }

            URI jsUri = URI.create(jsUrl);
            PolicyDecision decision = policyEngine.evaluate(jsUri, context.mode(), context.scopeAsset());
            if (!decision.allowed() || decision.resolvedIp() == null) {
                log.warn("Skipping prohibited or unresolvable JS URL: {}", jsUrl);
                rawTrace.append("SKIP (Policy Prohibited): ").append(jsUrl).append("\n");
                continue;
            }

            rawTrace.append("FETCH ").append(jsUrl).append(" (IP: ").append(decision.resolvedIp().getHostAddress()).append(")\n");

            if (hostRateLimiter != null) {
                String host = jsUri.getHost() != null ? jsUri.getHost() : "localhost";
                hostRateLimiter.acquire(host);
            }

            PinnedProbeResult probeResult;
            try {
                probeResult = pinnedHttpClient.executeWithRedirects(
                        jsUri,
                        decision.resolvedIp(),
                        true,
                        context.mode(),
                        context.scopeAsset(),
                        WIRE_CAP_PER_FILE,
                        DECOMPRESSED_CAP_PER_FILE,
                        READ_TIMEOUT_MS,
                        aggregateBudget
                );
            } catch (PayloadLimitExceededException plee) {
                boolean isAggregate = aggregateBudget.getConsumedBytes() > aggregateBudget.getMaxBytes()
                        || (plee.getMessage() != null && plee.getMessage().contains("Aggregate payload budget exceeded"));
                if (isAggregate) {
                    log.warn("Aggregate payload limit exceeded while downloading {}: {}", jsUrl, plee.getMessage());
                    rawTrace.append("STOPPED: Aggregate payload budget exceeded (").append(plee.getMessage()).append(")\n");
                    break;
                } else {
                    log.warn("Per-file payload limit exceeded while downloading {}: {}", jsUrl, plee.getMessage());
                    rawTrace.append("SKIPPED (File payload limit exceeded): ").append(jsUrl).append(" (").append(plee.getMessage()).append(")\n");
                    continue;
                }
            } catch (IOException | PolicyViolationException ex) {
                log.debug("I/O error fetching JS URL {}: {}", jsUrl, ex.getMessage());
                rawTrace.append("ERROR fetching ").append(jsUrl).append(": ").append(ex.getMessage()).append("\n");
                continue;
            }

            filesScanned++;
            String bodyText = probeResult.bodyText();
            if (bodyText.isBlank()) {
                continue;
            }

            String[] lines = bodyText.split("\\r?\\n");
            for (int i = 0; i < lines.length; i++) {
                int lineNum = i + 1;
                String line = lines[i];

                scanLineForSecrets(line, lineNum, jsUrl, findings, observations, rawTrace);
            }
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("filesScanned", filesScanned);
        parsedData.put("totalSecretsFound", findings.size());
        parsedData.put("findings", findings);

        String truncatedRaw = Utf8StringUtils.truncateUtf8(rawTrace.toString(), Utf8StringUtils.MAX_RAW_OUTPUT_BYTES);

        return new ToolExecutionOutcome(
                truncatedRaw,
                parsedData,
                null,
                false,
                observations
        );
    }

    private void scanLineForSecrets(String line, int lineNum, String fileUrl,
                                    List<Map<String, Object>> findings,
                                    List<ObservationDraft> observations,
                                    StringBuilder rawTrace) {
        boolean specificMatched = false;

        // 1. AWS Key
        Matcher awsMatcher = AWS_KEY_PATTERN.matcher(line);
        while (awsMatcher.find()) {
            addFinding("AWS Access Key ID", awsMatcher.group(), lineNum, fileUrl, "HIGH", findings, observations, rawTrace);
            specificMatched = true;
        }

        // 2. Google Cloud Key
        Matcher gcpMatcher = GCP_KEY_PATTERN.matcher(line);
        while (gcpMatcher.find()) {
            addFinding("Google Cloud API Key", gcpMatcher.group(), lineNum, fileUrl, "HIGH", findings, observations, rawTrace);
            specificMatched = true;
        }

        // 3. Stripe Key
        Matcher stripeMatcher = STRIPE_KEY_PATTERN.matcher(line);
        while (stripeMatcher.find()) {
            String match = stripeMatcher.group();
            String severity = match.contains("_live_") ? "CRITICAL" : "HIGH";
            addFinding("Stripe Secret Key", match, lineNum, fileUrl, severity, findings, observations, rawTrace);
            specificMatched = true;
        }

        // 4. GitHub PAT
        Matcher ghMatcher = GITHUB_PAT_PATTERN.matcher(line);
        while (ghMatcher.find()) {
            addFinding("GitHub Personal Access Token", ghMatcher.group(), lineNum, fileUrl, "HIGH", findings, observations, rawTrace);
            specificMatched = true;
        }

        // 5. Slack Token / Webhook
        Matcher slackMatcher = SLACK_TOKEN_PATTERN.matcher(line);
        while (slackMatcher.find()) {
            addFinding("Slack Token / Webhook", slackMatcher.group(), lineNum, fileUrl, "HIGH", findings, observations, rawTrace);
            specificMatched = true;
        }

        // 6. Private Key
        Matcher pkMatcher = PRIVATE_KEY_PATTERN.matcher(line);
        while (pkMatcher.find()) {
            addFinding("Private Key", pkMatcher.group(), lineNum, fileUrl, "CRITICAL", findings, observations, rawTrace);
            specificMatched = true;
        }

        // 7. JWT
        Matcher jwtMatcher = JWT_PATTERN.matcher(line);
        while (jwtMatcher.find()) {
            addFinding("JSON Web Token (JWT)", jwtMatcher.group(), lineNum, fileUrl, "MEDIUM", findings, observations, rawTrace);
            specificMatched = true;
        }

        // 8. Hardcoded High-Entropy Secret (only if no specific pattern matched on this line)
        if (!specificMatched) {
            Matcher entropyMatcher = ENTROPY_ASSIGNMENT_PATTERN.matcher(line);
            while (entropyMatcher.find()) {
                String candidate = entropyMatcher.group(1);
                if (candidate != null && candidate.length() >= 16) {
                    String candidateLower = candidate.toLowerCase(Locale.ROOT);
                    if (!candidateLower.contains("http") && !candidateLower.contains("function")
                            && !candidateLower.contains("undefined") && !candidateLower.contains("placeholder")
                            && !candidateLower.contains("example")) {
                        double entropy = calculateShannonEntropy(candidate);
                        if (entropy >= 3.5) {
                            addFinding("Hardcoded High-Entropy Secret", candidate, lineNum, fileUrl, "HIGH", findings, observations, rawTrace);
                        }
                    }
                }
            }
        }
    }

    private void addFinding(String secretType, String rawSecret, int lineNum, String fileUrl, String severity,
                            List<Map<String, Object>> findings,
                            List<ObservationDraft> observations,
                            StringBuilder rawTrace) {
        String masked = maskSecret(rawSecret);

        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("file", fileUrl);
        finding.put("secretType", secretType);
        finding.put("match", masked);
        finding.put("line", lineNum);
        finding.put("severity", severity);
        findings.add(finding);

        SeverityHeuristic severityHeuristic = toSeverityHeuristic(severity);
        observations.add(new ObservationDraft(
                "JS_SECRET_LEAK",
                "Found " + secretType + " in " + fileUrl + " at line " + lineNum + ": " + masked,
                severityHeuristic
        ));

        rawTrace.append("SECRET DETECTED [").append(severity).append("]: ").append(secretType)
                .append(" in ").append(fileUrl).append(":").append(lineNum).append(" -> ").append(masked).append("\n");
    }

    public static String maskSecret(String raw) {
        if (raw == null || raw.length() <= 6) {
            return "***masked***";
        }
        if (raw.startsWith("-----BEGIN")) {
            return "-----BEGIN ***masked*** PRIVATE KEY-----";
        }
        int prefixLen = Math.min(8, raw.length() / 3);
        return raw.substring(0, prefixLen) + "***masked***";
    }

    public static double calculateShannonEntropy(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : text.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int len = text.length();
        for (int count : freqMap.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private List<String> resolveJsUrls(ToolExecutionContext context, int maxFiles, AggregatePayloadBudget aggregateBudget) throws Exception {
        Map<String, Object> inputParams = context.inputParams();

        @SuppressWarnings("unchecked")
        List<String> explicitUrls = (List<String>) inputParams.get("jsUrls");

        // 1. Explicit jsUrls provided by operator
        if (explicitUrls != null && !explicitUrls.isEmpty()) {
            Set<String> unique = new LinkedHashSet<>();
            for (String url : explicitUrls) {
                if (url == null || url.isBlank()) {
                    continue;
                }
                String clean = url.trim();
                PolicyDecision decision = policyEngine.evaluate(URI.create(clean), context.mode(), context.scopeAsset());
                if (!decision.allowed()) {
                    throw new PolicyViolationException(
                            "Policy violation for jsUrl '" + clean + "': " + decision.reason(),
                            List.of(new InvalidParam("jsUrls", decision.reason()))
                    );
                }
                unique.add(clean);
                if (unique.size() >= maxFiles) {
                    break;
                }
            }
            return new ArrayList<>(unique);
        }

        // 2. Discover from completed extract_js_urls in the same session (strict BOLA isolation)
        List<ToolExecution> sessionExecutions = toolExecutionRepository.findBySessionIdOrderByCreatedAtAsc(context.sessionId());
        ToolExecution latestExtractJs = null;
        for (ToolExecution exec : sessionExecutions) {
            if ("extract_js_urls".equals(exec.getToolId()) && exec.getStatus() == ExecutionStatus.COMPLETED) {
                latestExtractJs = exec;
            }
        }

        Set<String> discoveredUrls = new LinkedHashSet<>();

        if (latestExtractJs != null) {
            Optional<ToolResult> resultOpt = toolResultRepository.findByExecutionId(latestExtractJs.getId());
            if (resultOpt.isPresent()) {
                Map<String, Object> parsed = resultOpt.get().getParsedData();
                Object scriptsObj = parsed.get("scripts");
                if (scriptsObj instanceof List<?> scriptList) {
                    for (Object item : scriptList) {
                        if (item instanceof Map<?, ?> map) {
                            Object srcObj = map.get("src");
                            if (srcObj instanceof String src && !src.isBlank()) {
                                PolicyDecision decision = policyEngine.evaluate(URI.create(src), context.mode(), context.scopeAsset());
                                if (decision.allowed()) {
                                    discoveredUrls.add(src);
                                    if (discoveredUrls.size() >= maxFiles) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Fallback: Harvest from landing page HTML
        if (discoveredUrls.isEmpty()) {
            URI baseUri = URI.create(context.targetUrl().trim());
            InetAddress pinnedIp;
            if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
                pinnedIp = context.policyDecision().resolvedIp();
            } else {
                PolicyDecision dec = policyEngine.evaluate(baseUri, context.mode(), context.scopeAsset());
                if (!dec.allowed() || dec.resolvedIp() == null) {
                    return Collections.emptyList();
                }
                pinnedIp = dec.resolvedIp();
            }

            try {
                PinnedProbeResult landingResult = pinnedHttpClient.executeWithRedirects(
                        baseUri,
                        pinnedIp,
                        true,
                        context.mode(),
                        context.scopeAsset(),
                        WIRE_CAP_PER_FILE,
                        DECOMPRESSED_CAP_PER_FILE,
                        READ_TIMEOUT_MS,
                        aggregateBudget
                );

                if (!landingResult.bodyText().isBlank()) {
                    Document doc = Jsoup.parse(landingResult.bodyText(), landingResult.finalUrl());
                    Elements scriptElements = doc.select("script[src]");
                    for (Element script : scriptElements) {
                        String src = script.absUrl("src").trim();
                        if (src.isBlank()) {
                            src = script.attr("src").trim();
                        }
                        if (!src.isBlank() && (src.startsWith("http://") || src.startsWith("https://"))) {
                            PolicyDecision dec = policyEngine.evaluate(URI.create(src), context.mode(), context.scopeAsset());
                            if (dec.allowed()) {
                                discoveredUrls.add(src);
                                if (discoveredUrls.size() >= maxFiles) {
                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                log.debug("Landing page harvest failed: {}", ex.getMessage());
            }
        }

        return new ArrayList<>(discoveredUrls);
    }

    private static int parseInteger(Object val) {
        if (val instanceof Integer i) {
            return i;
        }
        if (val instanceof Number n) {
            return n.intValue();
        }
        if (val instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return -1;
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
}
