package com.ospysin.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CidrBlockTest {

    @Test
    @DisplayName("Invalid CIDR formats throw IllegalArgumentException")
    void invalidCidrFormats() {
        assertThatThrownBy(() -> new CidrBlock("192.168.1.1", "missing slash"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new CidrBlock("invalid/24", "invalid ip"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new CidrBlock("192.168.1.1/33", "prefix too large for ipv4"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new CidrBlock("fe80::1/129", "prefix too large for ipv6"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> new CidrBlock("192.168.1.1/-1", "negative prefix"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "10.0.0.0/8, 10.1.2.3, true",
            "10.0.0.0/8, 11.0.0.1, false",
            "172.16.0.0/12, 172.16.0.1, true",
            "172.16.0.0/12, 172.31.255.255, true",
            "172.16.0.0/12, 172.32.0.1, false",
            "192.168.1.0/24, 192.168.1.254, true",
            "192.168.1.0/24, 192.168.2.1, false",
            "169.254.169.254/32, 169.254.169.254, true",
            "169.254.169.254/32, 169.254.169.253, false"
    })
    @DisplayName("IPv4 bitwise CIDR matching")
    void ipv4Matching(String cidr, String targetIp, boolean expected) throws UnknownHostException {
        CidrBlock block = new CidrBlock(cidr, "test");
        assertThat(block.matches(InetAddress.getByName(targetIp))).isEqualTo(expected);
        assertThat(block.getCidr()).isEqualTo(cidr);
        assertThat(block.getDescription()).isEqualTo("test");
        assertThat(block.toString()).contains(cidr);
    }

    @ParameterizedTest
    @CsvSource({
            "fe80::/10, fe80::1, true",
            "fe80::/10, febf::ffff, true",
            "fe80::/10, fec0::1, false",
            "fc00::/7, fc00::1, true",
            "fc00::/7, fdff:ffff::1, true",
            "fc00::/7, fe00::1, false",
            "::/128, ::, true",
            "::/128, ::1, false"
    })
    @DisplayName("IPv6 bitwise CIDR matching")
    void ipv6Matching(String cidr, String targetIp, boolean expected) throws UnknownHostException {
        CidrBlock block = new CidrBlock(cidr, "test");
        assertThat(block.matches(InetAddress.getByName(targetIp))).isEqualTo(expected);
    }

    @Test
    @DisplayName("Cross-family matching returns false and null address returns false")
    void crossFamilyAndNull() throws UnknownHostException {
        CidrBlock v4Block = new CidrBlock("192.168.1.0/24", "v4");
        CidrBlock v6Block = new CidrBlock("fe80::/10", "v6");

        assertThat(v4Block.matches(InetAddress.getByName("::1"))).isFalse();
        assertThat(v6Block.matches(InetAddress.getByName("192.168.1.1"))).isFalse();
        assertThat(v4Block.matches(null)).isFalse();
    }
}
