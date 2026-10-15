package com.ospysin.tools.recon;

import java.util.Collections;
import java.util.List;

/**
 * Structured raw result resulting from WHOIS or RDAP lookups.
 */
public record WhoisRawResult(
        String rawOutput,
        String registrar,
        String createdDate,
        String expiresDate,
        List<String> nameServers,
        List<String> statuses,
        String sourceProtocol,
        List<String> referralChain
) {
    public WhoisRawResult {
        rawOutput = rawOutput != null ? rawOutput : "";
        registrar = registrar != null ? registrar : "Unknown";
        nameServers = nameServers != null ? List.copyOf(nameServers) : Collections.emptyList();
        statuses = statuses != null ? List.copyOf(statuses) : Collections.emptyList();
        sourceProtocol = sourceProtocol != null ? sourceProtocol : "WHOIS";
        referralChain = referralChain != null ? List.copyOf(referralChain) : Collections.emptyList();
    }
}
