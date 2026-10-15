package com.ospysin.tools.recon;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.shared.util.Utf8StringUtils;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.OspysinTool;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Tool #1: DNS Record Enumeration probe (dns_lookup).
 * Queries primary resource records (A, AAAA, MX, TXT, NS, CNAME, CAA, SOA, PTR)
 * for the target domain and evaluates SPF, DMARC, and CAA configurations.
 */
@Slf4j
@Component
public class DnsLookupTool implements OspysinTool {

    public static final String TOOL_ID = "dns_lookup";
    public static final int MAX_OUTPUT_BYTES = 32 * 1024; // 32 KB cap

    public static final Set<String> ALLOWED_RECORD_TYPES = Collections.unmodifiableSet(
            new LinkedHashSet<>(List.of("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "PTR"))
    );

    public static final List<String> DEFAULT_RECORD_TYPES = List.of(
            "A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA"
    );

    private static final Pattern SPF_RECORD_PATTERN = Pattern.compile("(?i)^\\s*v=spf1(?:\\s|$).*");
    private static final Pattern DMARC_RECORD_PATTERN = Pattern.compile("(?i)^\\s*v=dmarc1(?:\\s*;.*|\\s*$)");
    private static final Pattern PERMISSIVE_SPF_PATTERN = Pattern.compile("(?i)(?:^|\\s)[+?]all(?:\\s|$)");

    private final DnsLookupClient dnsLookupClient;

    @Autowired
    public DnsLookupTool(DnsLookupClient dnsLookupClient) {
        this.dnsLookupClient = Objects.requireNonNull(dnsLookupClient, "dnsLookupClient must not be null");
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

        if (params.containsKey("recordTypes")) {
            Object raw = params.get("recordTypes");
            if (raw == null) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("recordTypes", "recordTypes must not be null"))
                );
            }
            if (!(raw instanceof List<?> list)) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("recordTypes", "recordTypes must be a list"))
                );
            }
            if (list.isEmpty()) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("recordTypes", "recordTypes must not be empty"))
                );
            }

            for (Object item : list) {
                if (!(item instanceof String s) || s.trim().isEmpty()) {
                    throw new ValidationException(
                            "Validation error for " + TOOL_ID,
                            List.of(new InvalidParam("recordTypes", "recordTypes entries must be non-blank strings"))
                    );
                }
                String normalized = s.trim().toUpperCase(Locale.ROOT);
                if (!ALLOWED_RECORD_TYPES.contains(normalized)) {
                    throw new ValidationException(
                            "Validation error for " + TOOL_ID,
                            List.of(new InvalidParam("recordTypes", "Disallowed record type '" + s + "'. Allowed types: " + ALLOWED_RECORD_TYPES))
                    );
                }
            }
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        String host = extractHost(context.targetUrl());
        List<String> recordTypes = resolveRequestedRecordTypes(context.inputParams());

        boolean isIpLiteral = ObfuscatedIpParser.parse(host) != null;
        boolean isLocalHost = "localhost".equalsIgnoreCase(host) || host.endsWith(".local") || host.endsWith(".internal");
        boolean isDomain = !isIpLiteral && !isLocalHost;

        Map<String, List<String>> recordsMap = new LinkedHashMap<>();
        for (String recordType : recordTypes) {
            try {
                List<String> records = dnsLookupClient.queryRecords(host, recordType);
                recordsMap.put(recordType, records != null ? records : List.of());
            } catch (Exception ex) {
                log.debug("DNS query error for host '{}' recordType '{}': {}", host, recordType, ex.getMessage());
                recordsMap.put(recordType, List.of());
            }
        }

        // SPF detection
        boolean spfPresent = false;
        String detectedSpf = null;
        List<String> txtRecords = recordsMap.getOrDefault("TXT", List.of());
        for (String txt : txtRecords) {
            if (txt != null && SPF_RECORD_PATTERN.matcher(txt).matches()) {
                spfPresent = true;
                detectedSpf = txt;
                break;
            }
        }

        // DMARC detection (_dmarc.<domain>)
        boolean dmarcPresent = false;
        if (recordTypes.contains("TXT") && isDomain) {
            try {
                List<String> dmarcRecords = dnsLookupClient.queryRecords("_dmarc." + host, "TXT");
                if (dmarcRecords != null) {
                    for (String txt : dmarcRecords) {
                        if (txt != null && DMARC_RECORD_PATTERN.matcher(txt).matches()) {
                            dmarcPresent = true;
                            break;
                        }
                    }
                }
            } catch (Exception ex) {
                log.debug("DMARC query failed for '_dmarc.{}': {}", host, ex.getMessage());
            }
        }

        // CAA detection
        boolean caaPresent = false;
        List<String> caaRecords = recordsMap.getOrDefault("CAA", List.of());
        if (!caaRecords.isEmpty()) {
            caaPresent = true;
        }

        // Security Observations
        List<ObservationDraft> observations = new ArrayList<>();
        if (isDomain) {
            if (recordTypes.contains("TXT")) {
                if (!spfPresent) {
                    observations.add(new ObservationDraft(
                            "DNS_SECURITY",
                            "Missing SPF (v=spf1) TXT record on domain " + host,
                            SeverityHeuristic.LOW
                    ));
                } else if (detectedSpf != null && isPermissiveSpf(detectedSpf)) {
                    observations.add(new ObservationDraft(
                            "DNS_SECURITY",
                            "Permissive SPF policy (" + detectedSpf + ") allows unauthorized mail spoofing",
                            SeverityHeuristic.MEDIUM
                    ));
                }

                if (!dmarcPresent) {
                    observations.add(new ObservationDraft(
                            "DNS_SECURITY",
                            "Missing DMARC (v=DMARC1) record for _dmarc." + host,
                            SeverityHeuristic.LOW
                    ));
                }
            }

            if (recordTypes.contains("CAA") && !caaPresent) {
                observations.add(new ObservationDraft(
                        "DNS_SECURITY",
                        "No DNS Certification Authority Authorization (CAA) records configured",
                        SeverityHeuristic.INFO
                ));
            }
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("domain", host);
        parsedData.put("records", recordsMap);
        parsedData.put("spfPresent", spfPresent);
        parsedData.put("dmarcPresent", dmarcPresent);
        parsedData.put("caaPresent", caaPresent);

        String rawOutput = buildRawOutput(host, recordTypes, recordsMap);

        return new ToolExecutionOutcome(rawOutput, parsedData, null, false, observations);
    }

    private List<String> resolveRequestedRecordTypes(Map<String, Object> params) {
        if (params == null || !params.containsKey("recordTypes") || params.get("recordTypes") == null) {
            return DEFAULT_RECORD_TYPES;
        }

        Object raw = params.get("recordTypes");
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return DEFAULT_RECORD_TYPES;
        }

        Set<String> resolved = new LinkedHashSet<>();
        for (Object item : list) {
            if (item instanceof String s && !s.trim().isEmpty()) {
                String normalized = s.trim().toUpperCase(Locale.ROOT);
                if (ALLOWED_RECORD_TYPES.contains(normalized)) {
                    resolved.add(normalized);
                }
            }
        }

        return resolved.isEmpty() ? DEFAULT_RECORD_TYPES : new ArrayList<>(resolved);
    }

    private boolean isPermissiveSpf(String spf) {
        if (spf == null) {
            return false;
        }
        return PERMISSIVE_SPF_PATTERN.matcher(spf).find()
                || spf.contains("+all")
                || spf.contains("?all");
    }

    private String buildRawOutput(String host, List<String> recordTypes, Map<String, List<String>> recordsMap) {
        StringBuilder sb = new StringBuilder();
        sb.append("; DNS Record Enumeration for ").append(host).append("\n");
        sb.append("; Record Types: ").append(String.join(", ", recordTypes)).append("\n\n");

        for (Map.Entry<String, List<String>> entry : recordsMap.entrySet()) {
            sb.append("[").append(entry.getKey()).append("]\n");
            List<String> recs = entry.getValue();
            if (recs == null || recs.isEmpty()) {
                sb.append("  (none)\n");
            } else {
                for (String r : recs) {
                    sb.append("  ").append(r).append("\n");
                }
            }
            sb.append("\n");
        }

        String raw = sb.toString().trim();
        return Utf8StringUtils.truncateUtf8(raw, MAX_OUTPUT_BYTES);
    }

    private String extractHost(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return "";
        }
        String trimmed = targetUrl.trim().toLowerCase(Locale.ROOT);
        try {
            if (trimmed.contains("://")) {
                URI uri = URI.create(trimmed);
                if (uri.getHost() != null) {
                    trimmed = uri.getHost().toLowerCase(Locale.ROOT);
                }
            }
        } catch (Exception ignored) {
        }
        int slash = trimmed.indexOf('/');
        if (slash >= 0) {
            trimmed = trimmed.substring(0, slash);
        }
        int lastBracket = trimmed.lastIndexOf(']');
        if (lastBracket >= 0) {
            int colonAfter = trimmed.indexOf(':', lastBracket);
            if (colonAfter > 0) {
                trimmed = trimmed.substring(0, colonAfter);
            }
        } else {
            int firstColon = trimmed.indexOf(':');
            int lastColon = trimmed.lastIndexOf(':');
            if (firstColon >= 0 && firstColon == lastColon) {
                trimmed = trimmed.substring(0, firstColon);
            }
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        while (trimmed.endsWith(".") && trimmed.length() > 1) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}
