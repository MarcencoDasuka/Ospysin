package com.ospysin.tools.probes;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of a parsed Set-Cookie directive.
 */
public record ParsedCookie(
        String name,
        String value,
        boolean secure,
        boolean httpOnly,
        String sameSite,
        String path,
        String domain
) {
    public ParsedCookie {
        Objects.requireNonNull(name, "cookie name must not be null");
        value = value != null ? value : "";
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", name);
        map.put("secure", secure);
        map.put("httpOnly", httpOnly);
        map.put("sameSite", sameSite);
        map.put("path", path);
        map.put("domain", domain);
        return map;
    }
}
