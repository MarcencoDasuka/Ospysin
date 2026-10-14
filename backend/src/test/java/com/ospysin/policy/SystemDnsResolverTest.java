package com.ospysin.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SystemDnsResolverTest {

    @Test
    @DisplayName("SystemDnsResolver resolves localhost successfully")
    void resolveLocalhost() throws UnknownHostException {
        SystemDnsResolver resolver = new SystemDnsResolver();
        InetAddress[] addresses = resolver.resolveAll("localhost");

        assertThat(addresses).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("SystemDnsResolver throws UnknownHostException for invalid domain")
    void resolveInvalidDomain() {
        SystemDnsResolver resolver = new SystemDnsResolver();
        assertThatThrownBy(() -> resolver.resolveAll("999.999.999.999"))
                .isInstanceOf(UnknownHostException.class);
    }
}
