package com.ospysin.tools.probes;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Representation of a single HTTP response captured via PinnedHttpClient.
 */
public record PinnedHttpResponse(
        URI requestUri,
        int statusCode,
        String httpVersion,
        String reasonPhrase,
        Map<String, List<String>> headers,
        List<ParsedCookie> cookies,
        String rawStatusAndHeaders,
        byte[] bodyBytes
) {
    public PinnedHttpResponse {
        headers = headers != null ? Collections.unmodifiableMap(headers) : Collections.emptyMap();
        cookies = cookies != null ? List.copyOf(cookies) : Collections.emptyList();
        bodyBytes = bodyBytes != null ? bodyBytes.clone() : new byte[0];
    }
}
