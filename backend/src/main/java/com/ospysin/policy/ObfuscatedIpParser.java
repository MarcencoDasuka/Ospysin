package com.ospysin.policy;

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class ObfuscatedIpParser {

    private ObfuscatedIpParser() {
    }

    /**
     * Attempts to parse an IP literal (IPv4 standard, octal, hex, dword, or IPv6 bracketed/raw).
     * Returns null if the host string is a domain name rather than an IP literal.
     */
    public static InetAddress parse(String host) {
        if (host == null || host.isBlank()) {
            return null;
        }

        String trimmed = host.trim();
        while (trimmed.endsWith(".") && trimmed.length() > 1) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }

        // Handle IPv6 literal [::1] or ::1
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            String inner = trimmed.substring(1, trimmed.length() - 1);
            try {
                InetAddress addr = InetAddress.getByName(inner);
                return addr;
            } catch (UnknownHostException e) {
                return null;
            }
        }
        if (trimmed.contains(":")) {
            try {
                return InetAddress.getByName(trimmed);
            } catch (UnknownHostException e) {
                return null;
            }
        }

        // Handle IPv4 (standard, octal, hex, decimal integer, 1 to 4 parts)
        String[] parts = trimmed.split("\\.", -1);
        if (parts.length < 1 || parts.length > 4) {
            return null;
        }

        long[] values = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            if (p.isEmpty()) {
                return null;
            }
            try {
                if (p.startsWith("0x") || p.startsWith("0X")) {
                    values[i] = Long.parseLong(p.substring(2), 16);
                } else if (p.startsWith("0") && p.length() > 1) {
                    values[i] = Long.parseLong(p, 8);
                } else {
                    values[i] = Long.parseLong(p, 10);
                }
            } catch (NumberFormatException e) {
                return null;
            }
        }

        long val;
        if (parts.length == 1) {
            if (values[0] < 0 || values[0] > 0xFFFFFFFFL) {
                return null;
            }
            val = values[0];
        } else if (parts.length == 2) {
            if (values[0] < 0 || values[0] > 255 || values[1] < 0 || values[1] > 0xFFFFFFL) {
                return null;
            }
            val = (values[0] << 24) | values[1];
        } else if (parts.length == 3) {
            if (values[0] < 0 || values[0] > 255 || values[1] < 0 || values[1] > 255 || values[2] < 0 || values[2] > 0xFFFFL) {
                return null;
            }
            val = (values[0] << 24) | (values[1] << 16) | values[2];
        } else {
            for (int i = 0; i < 4; i++) {
                if (values[i] < 0 || values[i] > 255) {
                    return null;
                }
            }
            val = (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3];
        }

        byte[] bytes = new byte[]{
                (byte) ((val >> 24) & 0xFF),
                (byte) ((val >> 16) & 0xFF),
                (byte) ((val >> 8) & 0xFF),
                (byte) (val & 0xFF)
        };

        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
