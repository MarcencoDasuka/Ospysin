package com.ospysin.policy;

import com.ospysin.sessions.SessionMode;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;

@Component
public class IpRangeValidator {

    private static final List<CidrBlock> UNCONDITIONAL_BLOCKED_CIDRS = List.of(
            // Cloud Metadata
            new CidrBlock("169.254.169.254/32", "AWS/GCP/Azure Cloud Metadata"),
            new CidrBlock("100.100.100.200/32", "Alibaba Cloud Metadata"),
            new CidrBlock("fd00:ec2::254/128", "AWS EC2 IPv6 Metadata"),

            // Link-Local
            new CidrBlock("169.254.0.0/16", "IPv4 Link-Local (RFC 3927)"),
            new CidrBlock("fe80::/10", "IPv6 Link-Local (RFC 4291)"),

            // Shared Address Space / CGNAT
            new CidrBlock("100.64.0.0/10", "Shared Address Space / CGNAT (RFC 6598)"),

            // Documentation & Benchmarking
            new CidrBlock("192.0.2.0/24", "TEST-NET-1 Documentation (RFC 5737)"),
            new CidrBlock("198.51.100.0/24", "TEST-NET-2 Documentation (RFC 5737)"),
            new CidrBlock("203.0.113.0/24", "TEST-NET-3 Documentation (RFC 5737)"),
            new CidrBlock("198.18.0.0/15", "Network Interconnect Benchmark (RFC 2544)"),
            new CidrBlock("2001:db8::/32", "IPv6 Documentation (RFC 3849)"),
            new CidrBlock("2001:2::/48", "BMWG Benchmarking (RFC 5180)"),
            new CidrBlock("2001:10::/28", "ORCHIDv2 (RFC 7343)"),

            // IPv6 Transition & Special-Purpose
            new CidrBlock("64:ff9b::/96", "NAT64 Translation (RFC 6052)"),
            new CidrBlock("64:ff9b:1::/48", "Local-Use NAT64 Translation (RFC 8215)"),
            new CidrBlock("2002::/16", "6to4 Transition (RFC 3056)"),
            new CidrBlock("100::/64", "Discard-Only (RFC 6666)"),

            // Multicast, Broadcast & Reserved
            new CidrBlock("224.0.0.0/4", "IPv4 Multicast (RFC 5771)"),
            new CidrBlock("240.0.0.0/4", "IPv4 Reserved (RFC 1112)"),
            new CidrBlock("255.255.255.255/32", "IPv4 Limited Broadcast (RFC 919)"),
            new CidrBlock("0.0.0.0/8", "This host on this network (RFC 1122)"),
            new CidrBlock("ff00::/8", "IPv6 Multicast (RFC 4291)"),
            new CidrBlock("::/128", "IPv6 Unspecified Address (RFC 4291)")
    );

    private static final List<CidrBlock> PUBLIC_ONLY_BLOCKED_CIDRS = List.of(
            // Loopback
            new CidrBlock("127.0.0.0/8", "IPv4 Loopback (RFC 1122)"),
            new CidrBlock("::1/128", "IPv6 Loopback (RFC 4291)"),

            // Private RFC 1918
            new CidrBlock("10.0.0.0/8", "RFC 1918 Private 24-bit block"),
            new CidrBlock("172.16.0.0/12", "RFC 1918 Private 20-bit block"),
            new CidrBlock("192.168.0.0/16", "RFC 1918 Private 16-bit block"),

            // Unique Local IPv6 (ULA)
            new CidrBlock("fc00::/7", "IPv6 Unique Local Address (RFC 4193)")
    );

    /**
     * Unwraps IPv4-mapped (::ffff:0:0/96) and deprecated IPv4-compatible (::/96) IPv6 addresses
     * to their underlying 4-byte IPv4 representation. Pure :: and ::1 remain pure IPv6 addresses.
     */
    public InetAddress unwrapIpv4Mapped(InetAddress address) {
        if (address == null) {
            return null;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 16) {
            // 1. IPv4-mapped IPv6: ::ffff:0:0/96
            boolean isMapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isMapped = false;
                    break;
                }
            }
            if (isMapped && bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF) {
                byte[] ipv4 = new byte[4];
                System.arraycopy(bytes, 12, ipv4, 0, 4);
                try {
                    return InetAddress.getByAddress(ipv4);
                } catch (UnknownHostException ignored) {
                    return address;
                }
            }

            // 2. Deprecated IPv4-compatible IPv6: ::/96 (excluding :: and ::1)
            boolean isCompatible = true;
            for (int i = 0; i < 12; i++) {
                if (bytes[i] != 0) {
                    isCompatible = false;
                    break;
                }
            }
            if (isCompatible) {
                boolean isAllZeros = (bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 0);
                boolean isLoopback = (bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 1);
                if (!isAllZeros && !isLoopback) {
                    byte[] ipv4 = new byte[4];
                    System.arraycopy(bytes, 12, ipv4, 0, 4);
                    try {
                        return InetAddress.getByAddress(ipv4);
                    } catch (UnknownHostException ignored) {
                        return address;
                    }
                }
            }
        }
        return address;
    }

    /**
     * Validates an IP address against the policy rules for the specified session mode.
     * Returns an Optional containing the denial reason if blocked, or Optional.empty() if allowed.
     */
    public Optional<String> validate(InetAddress address, SessionMode mode) {
        if (address == null) {
            return Optional.of("Resolved IP address is null");
        }
        if (mode == null) {
            return Optional.of("Session mode is required");
        }

        InetAddress unwrapped = unwrapIpv4Mapped(address);

        // 1. Unconditionally blocked in BOTH LOCAL and PUBLIC modes
        for (CidrBlock block : UNCONDITIONAL_BLOCKED_CIDRS) {
            if (block.matches(unwrapped)) {
                return Optional.of("Prohibited IP range: " + block.getDescription() + " (" + unwrapped.getHostAddress() + ")");
            }
        }

        // 2. Blocked in PUBLIC mode, Allowed in LOCAL mode
        if (mode == SessionMode.PUBLIC) {
            for (CidrBlock block : PUBLIC_ONLY_BLOCKED_CIDRS) {
                if (block.matches(unwrapped)) {
                    return Optional.of("Prohibited in PUBLIC mode: " + block.getDescription() + " (" + unwrapped.getHostAddress() + ")");
                }
            }
        }

        return Optional.empty();
    }

    public boolean isAllowed(InetAddress address, SessionMode mode) {
        return validate(address, mode).isEmpty();
    }
}
