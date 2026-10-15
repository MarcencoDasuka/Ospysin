package com.ospysin.tools.probes;

import java.util.Locale;

/**
 * Parser for HTTP Set-Cookie header directives.
 */
public final class CookieParser {

    private CookieParser() {
    }

    /**
     * Parses a single Set-Cookie header value into a structured ParsedCookie.
     *
     * @param headerValue the raw Set-Cookie header string
     * @return the parsed cookie, or null if the header is blank or malformed
     */
    public static ParsedCookie parse(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return null;
        }

        String[] parts = headerValue.split(";");
        if (parts.length == 0) {
            return null;
        }

        String nameValue = parts[0].trim();
        if (nameValue.isEmpty()) {
            return null;
        }

        String name;
        String value = "";
        int eqIdx = nameValue.indexOf('=');
        if (eqIdx >= 0) {
            name = nameValue.substring(0, eqIdx).trim();
            value = nameValue.substring(eqIdx + 1).trim();
        } else {
            name = nameValue;
        }

        if (name.isEmpty()) {
            return null;
        }

        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = null;
        String path = null;
        String domain = null;

        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            if (attr.isEmpty()) {
                continue;
            }

            int attrEqIdx = attr.indexOf('=');
            String attrName;
            String attrVal = "";
            if (attrEqIdx >= 0) {
                attrName = attr.substring(0, attrEqIdx).trim().toLowerCase(Locale.ROOT);
                attrVal = attr.substring(attrEqIdx + 1).trim();
                // Strip surrounding quotes if present
                if (attrVal.startsWith("\"") && attrVal.endsWith("\"") && attrVal.length() >= 2) {
                    attrVal = attrVal.substring(1, attrVal.length() - 1);
                }
            } else {
                attrName = attr.toLowerCase(Locale.ROOT);
            }

            switch (attrName) {
                case "secure" -> secure = true;
                case "httponly" -> httpOnly = true;
                case "samesite" -> sameSite = attrVal;
                case "path" -> path = attrVal;
                case "domain" -> domain = attrVal;
                default -> {
                    // Ignore other attributes (Expires, Max-Age, etc.)
                }
            }
        }

        return new ParsedCookie(name, value, secure, httpOnly, sameSite, path, domain);
    }
}
