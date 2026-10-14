package com.ospysin.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class ObfuscatedIpParserTest {

    @ParameterizedTest
    @CsvSource({
            "127.0.0.1, 127.0.0.1",
            "0177.0.0.1, 127.0.0.1",
            "0177.0.0.01, 127.0.0.1",
            "0x7f000001, 127.0.0.1",
            "0x7f.0.0.1, 127.0.0.1",
            "0x7f.0x0.0x0.0x1, 127.0.0.1",
            "2130706433, 127.0.0.1",
            "127.1, 127.0.0.1",
            "127.0.1, 127.0.0.1",
            "012.0.0.1, 10.0.0.1",
            "0xa9fea9fe, 169.254.169.254",
            "0xa9.0xfe.0xa9.0xfe, 169.254.169.254"
    })
    @DisplayName("Obfuscated IPv4 formats are parsed to standard IPv4 addresses")
    void parseObfuscatedIpv4(String input, String expected) {
        InetAddress parsed = ObfuscatedIpParser.parse(input);
        assertThat(parsed).isNotNull();
        assertThat(parsed.getHostAddress()).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"[::1]", "[fe80::1]", "[fd00:ec2::254]", "::1", "2001:db8::1"})
    @DisplayName("IPv6 literals (raw and bracketed) are parsed correctly")
    void parseIpv6Literals(String input) {
        InetAddress parsed = ObfuscatedIpParser.parse(input);
        assertThat(parsed).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "example.com",
            "sub.domain.org",
            "localhost",
            "invalid.123",
            "256.0.0.1",
            "",
            "   "
    })
    @DisplayName("Hostnames and invalid literals return null")
    void nonIpReturnsNull(String input) {
        assertThat(ObfuscatedIpParser.parse(input)).isNull();
    }
}
