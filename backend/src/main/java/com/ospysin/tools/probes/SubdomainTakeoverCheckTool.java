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
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.shared.util.Utf8StringUtils;
import com.ospysin.tools.*;
import com.ospysin.tools.recon.DnsLookupClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Tool #15: Subdomain Takeover & Dangling DNS probe.
 * Inspects CNAME records of target subdomains for dangling pointers to unclaimed
 * third-party cloud services, probing destination HTTP endpoints for canonical fingerprints.
 */
@Component
public class SubdomainTakeoverCheckTool implements OspysinTool {

    private static final Logger log = LoggerFactory.getLogger(SubdomainTakeoverCheckTool.class);

    public static final String TOOL_ID = "subdomain_takeover_check";
    public static final long WIRE_CAP_BYTES = 64 * 1024L; // 64 KB
    public static final long DECOMPRESSED_CAP_BYTES = 64 * 1024L; // 64 KB
    public static final int READ_TIMEOUT_MS = 15_000; // 15s
    public static final int MAX_SUBDOMAINS = 25;

    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+$");

    private record CloudProviderDef(
            String name,
            List<String> suffixes,
            List<String> fingerprints
    ) {}

    private static final List<CloudProviderDef> CLOUD_PROVIDERS = List.of(
            new CloudProviderDef("AWS S3",
                    List.of(".s3.amazonaws.com", ".amazonaws.com"),
                    List.of("NoSuchBucket", "The specified bucket does not exist")),
            new CloudProviderDef("GitHub Pages",
                    List.of(".github.io"),
                    List.of("There isn't a GitHub Pages site here")),
            new CloudProviderDef("Heroku",
                    List.of(".herokuapp.com", ".herokudns.com"),
                    List.of("No such app", "no-such-app.html")),
            new CloudProviderDef("Vercel",
                    List.of(".vercel.app", ".now.sh"),
                    List.of("The deployment could not be found", "404: NOT_FOUND")),
            new CloudProviderDef("Azure",
                    List.of(".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"),
                    List.of("404 Web Site not found", "Error 404 - Web app not found")),
            new CloudProviderDef("Fastly",
                    List.of(".fastly.net"),
                    List.of("Fastly error: unknown domain")),
            new CloudProviderDef("CloudFront",
                    List.of(".cloudfront.net"),
                    List.of("Bad request"))
    );

    private final DnsLookupClient dnsLookupClient;
    private final PinnedHttpClient pinnedHttpClient;
    private final PolicyEngine policyEngine;
    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;
    private final HostRateLimiter hostRateLimiter;

    @Autowired
    public SubdomainTakeoverCheckTool(DnsLookupClient dnsLookupClient,
                                      PinnedHttpClient pinnedHttpClient,
                                      PolicyEngine policyEngine,
                                      ToolExecutionRepository toolExecutionRepository,
                                      ToolResultRepository toolResultRepository,
                                      HostRateLimiter hostRateLimiter) {
        this.dnsLookupClient = Objects.requireNonNull(dnsLookupClient, "dnsLookupClient must not be null");
        this.pinnedHttpClient = Objects.requireNonNull(pinnedHttpClient, "pinnedHttpClient must not be null");
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.toolExecutionRepository = Objects.requireNonNull(toolExecutionRepository, "toolExecutionRepository must not be null");
        this.toolResultRepository = Objects.requireNonNull(toolResultRepository, "toolResultRepository must not be null");
        this.hostRateLimiter = hostRateLimiter;
    }

    public SubdomainTakeoverCheckTool(DnsLookupClient dnsLookupClient,
                                      PinnedHttpClient pinnedHttpClient,
                                      PolicyEngine policyEngine,
                                      ToolExecutionRepository toolExecutionRepository,
                                      ToolResultRepository toolResultRepository) {
        this(dnsLookupClient, pinnedHttpClient, policyEngine, toolExecutionRepository, toolResultRepository, null);
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

        if (params.containsKey("subdomains")) {
            Object val = params.get("subdomains");
            if (val == null) {
                errors.add(new InvalidParam("subdomains", "subdomains must not be null"));
            } else if (!(val instanceof List<?> list)) {
                errors.add(new InvalidParam("subdomains", "subdomains must be a list"));
            } else {
                if (list.size() > MAX_SUBDOMAINS) {
                    errors.add(new InvalidParam("subdomains", "subdomains list must contain at most " + MAX_SUBDOMAINS + " items"));
                }
                for (int i = 0; i < list.size(); i++) {
                    Object item = list.get(i);
                    if (!(item instanceof String s) || s.isBlank() || s.length() > 253
                            || s.contains("://") || s.contains("/") || s.contains(":") || s.contains("\r")
                            || s.contains("\n") || !HOSTNAME_PATTERN.matcher(s.trim()).matches()) {
                        errors.add(new InvalidParam("subdomains",
                                "Subdomain at index " + i + " must be a valid DNS hostname (<= 253 chars, alphanumeric with dots and hyphens)"));
                        break;
                    }
                }
            }
        }

        if (!errors.isEmpty()) {
            throw new ValidationException("Parameter validation failed for subdomain_takeover_check", errors);
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        String targetHost = extractHost(context.targetUrl());
        if (targetHost.isEmpty()) {
            throw new IllegalArgumentException("Cannot extract target host from " + context.targetUrl());
        }

        Map<String, Object> inputParams = context.inputParams();
        @SuppressWarnings("unchecked")
        List<String> explicitSubdomains = (List<String>) inputParams.get("subdomains");

        List<String> candidateSubdomains;

        if (explicitSubdomains != null && !explicitSubdomains.isEmpty()) {
            Set<String> unique = new LinkedHashSet<>();
            for (String sub : explicitSubdomains) {
                if (sub == null || sub.isBlank()) {
                    continue;
                }
                String norm = normalizeDomain(sub);
                if (!norm.equalsIgnoreCase(targetHost) && !norm.endsWith("." + targetHost)) {
                    throw new PolicyViolationException(
                            "Subdomain '" + sub + "' is outside authorized scope for target '" + targetHost + "'",
                            List.of(new InvalidParam("subdomains", "Subdomain must belong to " + targetHost))
                    );
                }
                unique.add(norm);
                if (unique.size() >= MAX_SUBDOMAINS) {
                    break;
                }
            }
            candidateSubdomains = new ArrayList<>(unique);
        } else {
            candidateSubdomains = harvestSubdomains(context, targetHost);
        }

        List<Map<String, Object>> cnameRecordsChecked = new ArrayList<>();
        List<ObservationDraft> observations = new ArrayList<>();
        StringBuilder rawTrace = new StringBuilder();
        boolean isVulnerable = false;

        for (String domain : candidateSubdomains) {
            rawTrace.append("CHECK CNAME for ").append(domain).append("\n");

            List<String> cnames;
            try {
                cnames = dnsLookupClient.queryRecords(domain, "CNAME");
            } catch (Exception ex) {
                log.debug("DNS lookup failed for CNAME on {}: {}", domain, ex.getMessage());
                rawTrace.append("  DNS lookup failed: ").append(ex.getMessage()).append("\n");
                continue;
            }

            if (cnames == null || cnames.isEmpty()) {
                rawTrace.append("  No CNAME records found\n");
                continue;
            }

            for (String cnameRaw : cnames) {
                String cnameTarget = normalizeDomain(cnameRaw);
                rawTrace.append("  -> CNAME: ").append(cnameTarget).append("\n");

                CloudProviderDef matchedProvider = findProvider(cnameTarget);
                if (matchedProvider == null) {
                    rawTrace.append("  (Not a recognized cloud provider suffix)\n");
                    continue;
                }

                String providerName = matchedProvider.name();
                String status = "SECURE";
                String fingerprintDetected = null;

                int targetPort = -1;
                try {
                    URI targetUri = URI.create(context.targetUrl().trim());
                    targetPort = targetUri.getPort();
                } catch (Exception ignored) {
                }
                String portSuffix = (targetPort != -1 && targetPort != 80 && targetPort != 443) ? (":" + targetPort) : "";

                // Evaluate policy with isSubdomainTakeoverCheck = true
                PolicyDecision probeDecision = policyEngine.evaluate("http://" + domain + portSuffix, context.mode(), context.scopeAsset(), true);
                if (!probeDecision.allowed() && (probeDecision.reason() != null
                        && (probeDecision.reason().startsWith("Unable to resolve") || probeDecision.reason().startsWith("No DNS records")))) {
                    // Try evaluating the CNAME target directly
                    probeDecision = policyEngine.evaluate("http://" + cnameTarget + portSuffix, context.mode(), context.scopeAsset(), true);
                }

                if (probeDecision.allowed() && probeDecision.resolvedIp() != null) {
                    if (hostRateLimiter != null) {
                        hostRateLimiter.acquire(domain);
                    }
                    try {
                        PinnedHttpResponse response = pinnedHttpClient.executeSingle(
                                URI.create("http://" + domain + portSuffix),
                                probeDecision.resolvedIp(),
                                WIRE_CAP_BYTES,
                                DECOMPRESSED_CAP_BYTES,
                                READ_TIMEOUT_MS
                        );

                        String bodyText = new String(response.bodyBytes(), StandardCharsets.UTF_8);

                        for (String fingerprint : matchedProvider.fingerprints()) {
                            if (bodyText.contains(fingerprint)) {
                                fingerprintDetected = fingerprint;
                                status = "VULNERABLE";
                                isVulnerable = true;
                                break;
                            }
                        }

                        if ("VULNERABLE".equals(status)) {
                            observations.add(new ObservationDraft(
                                    "SUBDOMAIN_TAKEOVER",
                                    "Subdomain takeover vulnerability on " + domain + " pointing to unclaimed " + providerName
                                            + " CNAME " + cnameTarget + " (fingerprint: '" + fingerprintDetected + "')",
                                    SeverityHeuristic.HIGH
                            ));
                            rawTrace.append("  [VULNERABLE] Matched fingerprint: '").append(fingerprintDetected).append("'\n");
                        } else {
                            rawTrace.append("  [SECURE] Destination responded without error fingerprint\n");
                        }

                    } catch (IOException ex) {
                        log.debug("HTTP probe failed for {}: {}", domain, ex.getMessage());
                        rawTrace.append("  HTTP probe failed: ").append(ex.getMessage()).append("\n");
                    }
                } else if (probeDecision.reason() != null
                        && (probeDecision.reason().startsWith("Unable to resolve") || probeDecision.reason().startsWith("No DNS records"))) {
                    status = "DANGLING_NXDOMAIN";
                    fingerprintDetected = "NXDOMAIN";
                    isVulnerable = true;
                    observations.add(new ObservationDraft(
                            "SUBDOMAIN_TAKEOVER",
                            "Dangling CNAME record on " + domain + " pointing to unresolvable target " + cnameTarget,
                            SeverityHeuristic.MEDIUM
                    ));
                    rawTrace.append("  [DANGLING_NXDOMAIN] Target does not resolve in DNS\n");
                } else {
                    status = "POLICY_BLOCKED";
                    rawTrace.append("  [POLICY_BLOCKED] Destination denied by PolicyEngine: ").append(probeDecision.reason()).append("\n");
                }

                Map<String, Object> recordEntry = new LinkedHashMap<>();
                recordEntry.put("domain", domain);
                recordEntry.put("cnameTarget", cnameTarget);
                recordEntry.put("provider", providerName);
                recordEntry.put("status", status);
                recordEntry.put("fingerprintDetected", fingerprintDetected);
                cnameRecordsChecked.add(recordEntry);
            }
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("isVulnerable", isVulnerable);
        parsedData.put("cnameRecordsChecked", cnameRecordsChecked);

        String truncatedRaw = Utf8StringUtils.truncateUtf8(rawTrace.toString(), Utf8StringUtils.MAX_RAW_OUTPUT_BYTES);

        return new ToolExecutionOutcome(
                truncatedRaw,
                parsedData,
                null,
                false,
                observations
        );
    }

    private CloudProviderDef findProvider(String cnameTarget) {
        String lower = cnameTarget.toLowerCase(Locale.ROOT);
        for (CloudProviderDef provider : CLOUD_PROVIDERS) {
            for (String suffix : provider.suffixes()) {
                if (lower.endsWith(suffix) || lower.equalsIgnoreCase(suffix.startsWith(".") ? suffix.substring(1) : suffix)) {
                    return provider;
                }
            }
        }
        return null;
    }

    private List<String> harvestSubdomains(ToolExecutionContext context, String targetHost) {
        Set<String> subdomains = new LinkedHashSet<>();
        subdomains.add(targetHost);

        List<ToolExecution> sessionExecutions = toolExecutionRepository.findBySessionIdOrderByCreatedAtAsc(context.sessionId());

        for (ToolExecution exec : sessionExecutions) {
            if (exec.getStatus() != ExecutionStatus.COMPLETED) {
                continue;
            }

            if ("tls_info".equals(exec.getToolId())) {
                Optional<ToolResult> resultOpt = toolResultRepository.findByExecutionId(exec.getId());
                if (resultOpt.isPresent()) {
                    Map<String, Object> parsed = resultOpt.get().getParsedData();
                    Object sanObj = parsed.get("sanEntries");
                    if (sanObj instanceof List<?> sanList) {
                        for (Object entry : sanList) {
                            if (entry instanceof String s) {
                                String clean = normalizeDomain(s);
                                if (clean.startsWith("*.")) {
                                    clean = clean.substring(2);
                                }
                                if (clean.equalsIgnoreCase(targetHost) || clean.endsWith("." + targetHost)) {
                                    subdomains.add(clean);
                                    if (subdomains.size() >= MAX_SUBDOMAINS) break;
                                }
                            }
                        }
                    }
                }
            } else if ("extract_links".equals(exec.getToolId())) {
                Optional<ToolResult> resultOpt = toolResultRepository.findByExecutionId(exec.getId());
                if (resultOpt.isPresent()) {
                    Map<String, Object> parsed = resultOpt.get().getParsedData();
                    extractHostsFromLinkList(parsed.get("internalLinks"), targetHost, subdomains);
                    extractHostsFromLinkList(parsed.get("externalLinks"), targetHost, subdomains);
                }
            }

            if (subdomains.size() >= MAX_SUBDOMAINS) {
                break;
            }
        }

        return new ArrayList<>(subdomains);
    }

    private void extractHostsFromLinkList(Object linksObj, String targetHost, Set<String> subdomains) {
        if (linksObj instanceof List<?> list) {
            for (Object link : list) {
                if (link instanceof String urlStr) {
                    String host = extractHost(urlStr);
                    if (!host.isEmpty() && (host.equalsIgnoreCase(targetHost) || host.endsWith("." + targetHost))) {
                        subdomains.add(host);
                        if (subdomains.size() >= MAX_SUBDOMAINS) break;
                    }
                }
            }
        }
    }

    private String normalizeDomain(String domain) {
        if (domain == null) return "";
        String trimmed = domain.trim().toLowerCase(Locale.ROOT);
        while (trimmed.endsWith(".") && trimmed.length() > 1) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private String extractHost(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        String clean = url.trim().toLowerCase(Locale.ROOT);
        try {
            if (clean.contains("://")) {
                URI uri = URI.create(clean);
                if (uri.getHost() != null) {
                    clean = uri.getHost();
                }
            }
        } catch (Exception ignored) {
        }
        int slash = clean.indexOf('/');
        if (slash >= 0) {
            clean = clean.substring(0, slash);
        }
        int lastBracket = clean.lastIndexOf(']');
        if (lastBracket >= 0) {
            int colonAfter = clean.indexOf(':', lastBracket);
            if (colonAfter > 0) {
                clean = clean.substring(0, colonAfter);
            }
        } else {
            int firstColon = clean.indexOf(':');
            int lastColon = clean.lastIndexOf(':');
            if (firstColon >= 0 && firstColon == lastColon) {
                clean = clean.substring(0, firstColon);
            }
        }
        if (clean.startsWith("[") && clean.endsWith("]")) {
            clean = clean.substring(1, clean.length() - 1);
        }
        return normalizeDomain(clean);
    }
}
