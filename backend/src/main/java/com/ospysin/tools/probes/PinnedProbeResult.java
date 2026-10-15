package com.ospysin.tools.probes;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Aggregated outcome of an HTTP probe execution, including any evaluated redirect hops.
 */
public record PinnedProbeResult(
        String finalUrl,
        int finalStatusCode,
        String httpVersion,
        Map<String, Object> normalizedHeaders,
        List<ParsedCookie> cookies,
        List<Map<String, Object>> redirectChain,
        String rawOutput
) {
    public PinnedProbeResult {
        normalizedHeaders = normalizedHeaders != null ? Collections.unmodifiableMap(normalizedHeaders) : Collections.emptyMap();
        cookies = cookies != null ? List.copyOf(cookies) : Collections.emptyList();
        redirectChain = redirectChain != null ? List.copyOf(redirectChain) : Collections.emptyList();
    }
}
