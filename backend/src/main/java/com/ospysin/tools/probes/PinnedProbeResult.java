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
        String rawOutput,
        byte[] bodyBytes
) {
    public PinnedProbeResult {
        normalizedHeaders = normalizedHeaders != null ? Collections.unmodifiableMap(normalizedHeaders) : Collections.emptyMap();
        cookies = cookies != null ? List.copyOf(cookies) : Collections.emptyList();
        redirectChain = redirectChain != null ? List.copyOf(redirectChain) : Collections.emptyList();
        bodyBytes = bodyBytes != null ? bodyBytes.clone() : new byte[0];
    }

    public PinnedProbeResult(
            String finalUrl,
            int finalStatusCode,
            String httpVersion,
            Map<String, Object> normalizedHeaders,
            List<ParsedCookie> cookies,
            List<Map<String, Object>> redirectChain,
            String rawOutput
    ) {
        this(finalUrl, finalStatusCode, httpVersion, normalizedHeaders, cookies, redirectChain, rawOutput, new byte[0]);
    }

    public String bodyText() {
        return new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    @Override
    public byte[] bodyBytes() {
        return bodyBytes != null ? bodyBytes.clone() : new byte[0];
    }
}
