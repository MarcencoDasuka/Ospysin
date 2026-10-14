package com.ospysin.policy;

import com.ospysin.sessions.SessionMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;

class IpRangeValidatorTest {

    private IpRangeValidator validator;

    @BeforeEach
    void setUp() {
        validator = new IpRangeValidator();
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "127.0.0.2", "127.255.255.255", "::1"})
    @DisplayName("Loopback addresses are ALLOWED in LOCAL mode and BLOCKED in PUBLIC mode")
    void loopbackAddresses(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL))
                .as("Loopback " + ip + " should be allowed in LOCAL mode")
                .isTrue();

        assertThat(validator.isAllowed(address, SessionMode.PUBLIC))
                .as("Loopback " + ip + " should be blocked in PUBLIC mode")
                .isFalse();

        assertThat(validator.validate(address, SessionMode.PUBLIC))
                .isPresent()
                .hasValueSatisfying(reason -> assertThat(reason).containsIgnoringCase("Loopback"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "10.0.0.1", "10.254.0.1", "10.255.255.255",
            "172.16.0.1", "172.24.0.1", "172.31.255.255",
            "192.168.0.1", "192.168.1.1", "192.168.255.255",
            "fc00::1", "fd00::1", "fd12:3456:789a:1::1"
    })
    @DisplayName("Private RFC 1918 and IPv6 ULA addresses are ALLOWED in LOCAL and BLOCKED in PUBLIC")
    void privateAndUlaAddresses(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL))
                .as("Private/ULA " + ip + " should be allowed in LOCAL mode")
                .isTrue();

        assertThat(validator.isAllowed(address, SessionMode.PUBLIC))
                .as("Private/ULA " + ip + " should be blocked in PUBLIC mode")
                .isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "169.254.169.254", // AWS/GCP/Azure/OpenStack metadata
            "100.100.100.200", // Alibaba Cloud metadata
            "fd00:ec2::254"     // AWS EC2 IPv6 metadata
    })
    @DisplayName("Cloud metadata endpoints are UNCONDITIONALLY BLOCKED in BOTH modes")
    void cloudMetadataBlockedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL))
                .as("Cloud metadata " + ip + " MUST be blocked in LOCAL mode")
                .isFalse();

        assertThat(validator.isAllowed(address, SessionMode.PUBLIC))
                .as("Cloud metadata " + ip + " MUST be blocked in PUBLIC mode")
                .isFalse();

        assertThat(validator.validate(address, SessionMode.LOCAL))
                .isPresent()
                .hasValueSatisfying(reason -> assertThat(reason).containsIgnoringCase("Metadata"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "169.254.0.1", "169.254.1.1", "169.254.255.254", // IPv4 Link-Local
            "fe80::1", "fe80::dead:beef"                       // IPv6 Link-Local
    })
    @DisplayName("Link-local addresses are UNCONDITIONALLY BLOCKED in BOTH modes")
    void linkLocalBlockedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL)).isFalse();
        assertThat(validator.isAllowed(address, SessionMode.PUBLIC)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"100.64.0.1", "100.100.0.1", "100.127.255.254"})
    @DisplayName("CGNAT / Shared Address Space (RFC 6598) is UNCONDITIONALLY BLOCKED in BOTH modes")
    void cgnatBlockedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL)).isFalse();
        assertThat(validator.isAllowed(address, SessionMode.PUBLIC)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "192.0.2.1", "192.0.2.254",       // TEST-NET-1 (RFC 5737)
            "198.51.100.1", "198.51.100.254", // TEST-NET-2 (RFC 5737)
            "203.0.113.1", "203.0.113.254",   // TEST-NET-3 (RFC 5737)
            "198.18.0.1", "198.19.255.254",   // Benchmark (RFC 2544)
            "2001:db8::1", "2001:db8:ffff::1" // Documentation IPv6 (RFC 3849)
    })
    @DisplayName("Documentation and Benchmarking ranges are UNCONDITIONALLY BLOCKED in BOTH modes")
    void documentationAndBenchmarkingBlockedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL)).isFalse();
        assertThat(validator.isAllowed(address, SessionMode.PUBLIC)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "224.0.0.1", "239.255.255.255", // IPv4 Multicast
            "240.0.0.1", "254.255.255.254", // IPv4 Reserved
            "255.255.255.255",               // IPv4 Limited Broadcast
            "0.0.0.0", "0.255.255.255",      // IPv4 "This host on this network"
            "ff00::1", "ff02::1",            // IPv6 Multicast
            "::"                             // IPv6 Unspecified
    })
    @DisplayName("Multicast, broadcast, reserved, and unspecified are UNCONDITIONALLY BLOCKED in BOTH modes")
    void multicastAndReservedBlockedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL)).isFalse();
        assertThat(validator.isAllowed(address, SessionMode.PUBLIC)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "64:ff9b::1",         // NAT64 (RFC 6052)
            "64:ff9b:1::1",       // Local-Use NAT64 (RFC 8215)
            "2002:7f00:1::1",     // 6to4 (RFC 3056)
            "100::1",             // Discard-Only (RFC 6666)
            "2001:2::1",          // BMWG Benchmarking (RFC 5180)
            "2001:10::1"          // ORCHIDv2 (RFC 7343)
    })
    @DisplayName("IPv6 transition and special-purpose ranges are UNCONDITIONALLY BLOCKED in BOTH modes")
    void ipv6TransitionRangesBlockedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL)).isFalse();
        assertThat(validator.isAllowed(address, SessionMode.PUBLIC)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
            "::ffff:127.0.0.1, true, false",
            "::ffff:169.254.169.254, false, false",
            "::ffff:192.168.1.1, true, false",
            "::ffff:93.184.216.34, true, true",
            "::127.0.0.1, true, false",
            "::169.254.169.254, false, false"
    })
    @DisplayName("IPv4-Mapped (::ffff:0:0/96) and IPv4-Compatible (::/96) IPv6 addresses are unwrapped and evaluated against IPv4 rules")
    void ipv4MappedIpv6Unwrapped(String ip, boolean expectedLocal, boolean expectedPublic) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL))
                .as("IPv4-mapped " + ip + " in LOCAL mode")
                .isEqualTo(expectedLocal);

        assertThat(validator.isAllowed(address, SessionMode.PUBLIC))
                .as("IPv4-mapped " + ip + " in PUBLIC mode")
                .isEqualTo(expectedPublic);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "93.184.216.34",                        // example.com
            "8.8.8.8",                              // Google DNS
            "1.1.1.1",                              // Cloudflare DNS
            "2606:2800:220:1:248:1893:25c8:1946",   // IPv6 example.com
            "2001:4860:4860::8888"                  // IPv6 Google DNS
    })
    @DisplayName("Public routable IP addresses are ALLOWED in BOTH LOCAL and PUBLIC modes")
    void publicRoutableAllowedInBothModes(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);

        assertThat(validator.isAllowed(address, SessionMode.LOCAL)).isTrue();
        assertThat(validator.isAllowed(address, SessionMode.PUBLIC)).isTrue();
    }

    @Test
    @DisplayName("Null address or null mode returns rejection reason")
    void nullHandling() throws UnknownHostException {
        assertThat(validator.validate(null, SessionMode.PUBLIC)).isPresent();
        assertThat(validator.validate(InetAddress.getByName("8.8.8.8"), null)).isPresent();
        assertThat(validator.isAllowed(null, SessionMode.PUBLIC)).isFalse();
        assertThat(validator.isAllowed(InetAddress.getByName("8.8.8.8"), null)).isFalse();
    }
}
