package com.ospysin.tools.probes;

import com.ospysin.policy.ObfuscatedIpParser;

import java.net.InetAddress;
import java.util.List;
import java.util.Locale;

/**
 * Service identity verifier for TLS certificates per RFC 9525 and RFC 6125.
 */
public final class Rfc9525Verifier {

    private Rfc9525Verifier() {
    }

    /**
     * Verifies targetHost against the certificate's SAN entries and optional Common Name.
     *
     * @param targetHost the reference identifier host
     * @param sanEntries list of Subject Alternative Name strings (DNS names and IP addresses)
     * @param commonName the subject DN Common Name (used strictly as fallback if sanEntries is empty)
     * @return true if targetHost matches the certificate identity per RFC 9525
     */
    public static boolean verifyHostname(String targetHost, List<String> sanEntries, String commonName) {
        if (targetHost == null || targetHost.isBlank()) {
            return false;
        }

        String normalizedHost = targetHost.trim().toLowerCase(Locale.ROOT);
        while (normalizedHost.endsWith(".") && normalizedHost.length() > 1) {
            normalizedHost = normalizedHost.substring(0, normalizedHost.length() - 1);
        }

        boolean isIp = ObfuscatedIpParser.parse(normalizedHost) != null;

        // If SAN entries exist, RFC 9525 forbids checking Common Name
        if (sanEntries != null && !sanEntries.isEmpty()) {
            for (String rawSan : sanEntries) {
                if (rawSan == null || rawSan.isBlank()) {
                    continue;
                }
                String san = rawSan.trim().toLowerCase(Locale.ROOT);
                while (san.endsWith(".") && san.length() > 1) {
                    san = san.substring(0, san.length() - 1);
                }

                if (isIp) {
                    // IP matching against IP SAN
                    if (matchIp(normalizedHost, san)) {
                        return true;
                    }
                } else {
                    // DNS matching against DNS SAN
                    if (matchDns(normalizedHost, san)) {
                        return true;
                    }
                }
            }
            return false;
        }

        // Fallback to Common Name only if SAN list is empty (legacy compatibility)
        if (commonName != null && !commonName.isBlank()) {
            String normalizedCn = commonName.trim().toLowerCase(Locale.ROOT);
            while (normalizedCn.endsWith(".") && normalizedCn.length() > 1) {
                normalizedCn = normalizedCn.substring(0, normalizedCn.length() - 1);
            }
            if (isIp) {
                return matchIp(normalizedHost, normalizedCn);
            } else {
                return matchDns(normalizedHost, normalizedCn);
            }
        }

        return false;
    }

    private static boolean matchDns(String host, String presented) {
        // Exact match
        if (host.equals(presented)) {
            return true;
        }

        // Wildcard match per RFC 9525 Section 6.4:
        // Wildcard MUST be in the left-most label (e.g. *.example.com)
        if (presented.startsWith("*.")) {
            String suffix = presented.substring(2); // "example.com"
            int dotIdx = host.indexOf('.');
            if (dotIdx > 0) {
                String firstLabel = host.substring(0, dotIdx);
                String hostSuffix = host.substring(dotIdx + 1);
                // Wildcard matches exactly one label (firstLabel must not contain any dot, and hostSuffix == suffix)
                if (hostSuffix.equals(suffix) && !firstLabel.isEmpty() && !firstLabel.contains(".")) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean matchIp(String hostIp, String presentedIp) {
        if (hostIp.equalsIgnoreCase(presentedIp)) {
            return true;
        }
        try {
            InetAddress a1 = InetAddress.getByName(hostIp);
            InetAddress a2 = InetAddress.getByName(presentedIp);
            return a1.equals(a2);
        } catch (Exception ignored) {
            return false;
        }
    }
}
