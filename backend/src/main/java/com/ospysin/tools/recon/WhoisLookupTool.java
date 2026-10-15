package com.ospysin.tools.recon;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.sessions.SessionMode;
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
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Tool #2: WHOIS / RDAP Registration Reconnaissance Tool (whois_lookup).
 * Queries authoritative WHOIS / RDAP registration directories for domain lifecycle and registrar records.
 */
@Slf4j
@Component
public class WhoisLookupTool implements OspysinTool {

    public static final String TOOL_ID = "whois_lookup";
    public static final int MAX_OUTPUT_BYTES = 32 * 1024; // 32 KB cap
    public static final int DEFAULT_REFERRAL_DEPTH = 1;

    private final WhoisQueryClient whoisQueryClient;
    private final IpRangeValidator ipRangeValidator;
    private final Clock clock;

    @Autowired
    public WhoisLookupTool(WhoisQueryClient whoisQueryClient, IpRangeValidator ipRangeValidator, Clock clock) {
        this.whoisQueryClient = Objects.requireNonNull(whoisQueryClient, "whoisQueryClient must not be null");
        this.ipRangeValidator = Objects.requireNonNull(ipRangeValidator, "ipRangeValidator must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public WhoisLookupTool(WhoisQueryClient whoisQueryClient, Clock clock) {
        this(whoisQueryClient, new IpRangeValidator(), clock);
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

        if (params.containsKey("referralDepth")) {
            Object raw = params.get("referralDepth");
            if (raw == null) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("referralDepth", "referralDepth must not be null"))
                );
            }

            int depth = parseStrictInt(raw);
            if (depth < 0 || depth > 3) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("referralDepth", "referralDepth must be an integer between 0 and 3"))
                );
            }
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        String host = extractHost(context.targetUrl());

        // Graceful handling of localhost / private IP addresses per Constraint 4
        InetAddress parsedIp = ObfuscatedIpParser.parse(host);
        boolean isLocalhost = "localhost".equalsIgnoreCase(host) || host.endsWith(".local") || host.endsWith(".internal");
        boolean isPrivateOrSpecialIp = parsedIp != null && !ipRangeValidator.isAllowed(parsedIp, SessionMode.PUBLIC);

        if (isLocalhost || isPrivateOrSpecialIp) {
            log.info("Target host '{}' is a local or private address; returning graceful unregistered outcome", host);
            Map<String, Object> parsedData = new LinkedHashMap<>();
            parsedData.put("domain", host);
            parsedData.put("registered", false);
            parsedData.put("registrar", "N/A");
            parsedData.put("createdDate", null);
            parsedData.put("expiresDate", null);
            parsedData.put("daysUntilExpiry", null);
            parsedData.put("nameServers", List.of());
            parsedData.put("statuses", List.of());
            parsedData.put("sourceProtocol", "NONE");
            parsedData.put("referralChain", List.of());
            String infoMessage = "Target host '" + host + "' is a local or private address; public WHOIS/RDAP registration records do not exist.";
            parsedData.put("raw", infoMessage);

            return new ToolExecutionOutcome(infoMessage, parsedData, null, false, List.of());
        }

        int referralDepth = DEFAULT_REFERRAL_DEPTH;
        if (context.inputParams().containsKey("referralDepth") && context.inputParams().get("referralDepth") != null) {
            try {
                referralDepth = parseStrictInt(context.inputParams().get("referralDepth"));
            } catch (ValidationException ignored) {
            }
            referralDepth = Math.max(0, Math.min(referralDepth, 3));
        }

        WhoisRawResult result = whoisQueryClient.query(host, referralDepth);

        // Compute daysUntilExpiry using injected Clock
        Long daysUntilExpiry = null;
        if (result.expiresDate() != null) {
            try {
                Instant expiryInstant = Instant.parse(result.expiresDate());
                daysUntilExpiry = ChronoUnit.DAYS.between(clock.instant(), expiryInstant);
            } catch (Exception ex) {
                log.debug("Could not parse expiresDate '{}' as Instant: {}", result.expiresDate(), ex.getMessage());
            }
        }

        // Security & Lifecycle Observations
        List<ObservationDraft> observations = new ArrayList<>();
        if (daysUntilExpiry != null) {
            if (daysUntilExpiry < 0) {
                observations.add(new ObservationDraft(
                        "WHOIS_LIFECYCLE",
                        "Domain registration expired " + Math.abs(daysUntilExpiry) + " days ago",
                        SeverityHeuristic.HIGH
                ));
            } else if (daysUntilExpiry <= 30) {
                observations.add(new ObservationDraft(
                        "WHOIS_LIFECYCLE",
                        "Domain registration expires in " + daysUntilExpiry + " days",
                        SeverityHeuristic.MEDIUM
                ));
            }
        }

        if (result.statuses() != null && !result.statuses().isEmpty()) {
            boolean hasTransferLock = result.statuses().stream()
                    .anyMatch(s -> s.toLowerCase(Locale.ROOT).contains("transferprohibited"));
            if (!hasTransferLock) {
                observations.add(new ObservationDraft(
                        "WHOIS_SECURITY",
                        "Domain does not have clientTransferProhibited lock enabled",
                        SeverityHeuristic.LOW
                ));
            }
        }

        String rawOutput = Utf8StringUtils.truncateUtf8(result.rawOutput(), MAX_OUTPUT_BYTES);

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("domain", host);
        parsedData.put("registrar", result.registrar() != null ? result.registrar() : "Unknown");
        parsedData.put("createdDate", result.createdDate());
        parsedData.put("expiresDate", result.expiresDate());
        parsedData.put("daysUntilExpiry", daysUntilExpiry);
        parsedData.put("nameServers", result.nameServers());
        parsedData.put("statuses", result.statuses());
        parsedData.put("sourceProtocol", result.sourceProtocol());
        parsedData.put("referralChain", result.referralChain());
        parsedData.put("raw", rawOutput);

        return new ToolExecutionOutcome(rawOutput, parsedData, null, false, observations);
    }

    private int parseStrictInt(Object raw) throws ValidationException {
        if (raw instanceof Byte b) {
            return b.intValue();
        }
        if (raw instanceof Short s) {
            return s.intValue();
        }
        if (raw instanceof Integer i) {
            return i;
        }
        if (raw instanceof Long l) {
            if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("referralDepth", "referralDepth must be an integer between 0 and 3"))
                );
            }
            return l.intValue();
        }
        if (raw instanceof String s) {
            try {
                long parsed = Long.parseLong(s.trim());
                if (parsed < Integer.MIN_VALUE || parsed > Integer.MAX_VALUE) {
                    throw new ValidationException(
                            "Validation error for " + TOOL_ID,
                            List.of(new InvalidParam("referralDepth", "referralDepth must be an integer between 0 and 3"))
                    );
                }
                return (int) parsed;
            } catch (NumberFormatException e) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("referralDepth", "referralDepth must be an integer between 0 and 3"))
                );
            }
        }
        throw new ValidationException(
                "Validation error for " + TOOL_ID,
                List.of(new InvalidParam("referralDepth", "referralDepth must be an integer between 0 and 3"))
        );
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
