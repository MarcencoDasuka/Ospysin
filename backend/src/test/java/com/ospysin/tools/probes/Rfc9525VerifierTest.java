package com.ospysin.tools.probes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class Rfc9525VerifierTest {

    @Test
    @DisplayName("Exact DNS SAN match (case-insensitive and trailing dots)")
    void exactDnsSanMatch() {
        List<String> sans = List.of("example.com", "api.example.com");

        assertThat(Rfc9525Verifier.verifyHostname("example.com", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("EXAMPLE.COM", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("example.com.", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("api.example.com", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("other.com", sans, null)).isFalse();
    }

    @Test
    @DisplayName("Wildcard DNS SAN matching per RFC 9525 Section 6.4")
    void wildcardDnsSanMatch() {
        List<String> sans = List.of("*.example.com");

        // Matches single left-most label
        assertThat(Rfc9525Verifier.verifyHostname("foo.example.com", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("bar.example.com", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("FOO.EXAMPLE.COM", sans, null)).isTrue();

        // Must NOT match parent domain
        assertThat(Rfc9525Verifier.verifyHostname("example.com", sans, null)).isFalse();

        // Must NOT match multi-level subdomain (wildcard matches exactly one label)
        assertThat(Rfc9525Verifier.verifyHostname("sub.sub.example.com", sans, null)).isFalse();
        assertThat(Rfc9525Verifier.verifyHostname("a.b.c.example.com", sans, null)).isFalse();

        // Wildcard must NOT match unrelated domain
        assertThat(Rfc9525Verifier.verifyHostname("notexample.com", sans, null)).isFalse();
    }

    @Test
    @DisplayName("IP SAN matching against IPv4 and IPv6 reference identifiers")
    void ipSanMatching() {
        List<String> sans = List.of("192.168.1.10", "127.0.0.1", "::1");

        assertThat(Rfc9525Verifier.verifyHostname("127.0.0.1", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("192.168.1.10", sans, null)).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("10.0.0.1", sans, null)).isFalse();

        // Wildcards are invalid for IP addresses
        List<String> invalidWildcardIpSans = List.of("*.168.1.10");
        assertThat(Rfc9525Verifier.verifyHostname("192.168.1.10", invalidWildcardIpSans, null)).isFalse();
    }

    @Test
    @DisplayName("Fallback to Common Name only when SAN list is empty")
    void fallbackToCommonNameWhenSanIsEmpty() {
        assertThat(Rfc9525Verifier.verifyHostname("legacy.example.com", Collections.emptyList(), "legacy.example.com")).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("sub.legacy.com", Collections.emptyList(), "*.legacy.com")).isTrue();
        assertThat(Rfc9525Verifier.verifyHostname("other.com", Collections.emptyList(), "legacy.example.com")).isFalse();
    }

    @Test
    @DisplayName("RFC 9525 ignores Common Name when SAN list is present")
    void ignoreCommonNameWhenSanIsPresent() {
        List<String> sans = List.of("valid.example.com");
        // CN matches, but SAN does not match -> must return false per RFC 9525!
        assertThat(Rfc9525Verifier.verifyHostname("cn-only.example.com", sans, "cn-only.example.com")).isFalse();
    }

    @Test
    @DisplayName("Rejects null, blank, or invalid target hosts")
    void rejectNullOrBlankTargetHost() {
        List<String> sans = List.of("example.com");
        assertThat(Rfc9525Verifier.verifyHostname(null, sans, null)).isFalse();
        assertThat(Rfc9525Verifier.verifyHostname("", sans, null)).isFalse();
        assertThat(Rfc9525Verifier.verifyHostname("   ", sans, null)).isFalse();
    }
}
