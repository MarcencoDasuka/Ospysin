package com.ospysin.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PinnedDnsResolverTest {

    @Test
    @DisplayName("PinnedDnsResolver with expectedHost resolves matching host and rejects others")
    void expectedHostResolution() throws UnknownHostException {
        InetAddress ip = InetAddress.getByName("93.184.216.34");
        PinnedDnsResolver resolver = new PinnedDnsResolver("Example.COM", ip);

        assertThat(resolver.getExpectedHost()).isEqualTo("example.com");
        assertThat(resolver.getPinnedAddress()).isEqualTo(ip);

        // Case-insensitive match succeeds
        InetAddress[] addresses = resolver.resolveAll("EXAMPLE.com");
        assertThat(addresses).containsExactly(ip);

        // Mismatched host throws UnknownHostException
        assertThatThrownBy(() -> resolver.resolveAll("attacker.com"))
                .isInstanceOf(UnknownHostException.class)
                .hasMessageContaining("does not match pinned host");

        // Null host throws UnknownHostException
        assertThatThrownBy(() -> resolver.resolveAll(null))
                .isInstanceOf(UnknownHostException.class);
    }

    @Test
    @DisplayName("PinnedDnsResolver without expectedHost resolves any host to pinned address")
    void wildResolver() throws UnknownHostException {
        InetAddress ip = InetAddress.getByName("93.184.216.34");
        PinnedDnsResolver resolver = new PinnedDnsResolver(ip);

        assertThat(resolver.getExpectedHost()).isNull();
        assertThat(resolver.getPinnedAddress()).isEqualTo(ip);

        assertThat(resolver.resolveAll("any-host.org")).containsExactly(ip);
        assertThat(resolver.resolveAll("another.com")).containsExactly(ip);
    }

    @Test
    @DisplayName("Constructor rejects null arguments")
    void nullArgumentsRejected() throws UnknownHostException {
        InetAddress ip = InetAddress.getByName("127.0.0.1");

        assertThatThrownBy(() -> new PinnedDnsResolver(null, ip))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> new PinnedDnsResolver("host", null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> new PinnedDnsResolver((InetAddress) null))
                .isInstanceOf(NullPointerException.class);
    }
}
