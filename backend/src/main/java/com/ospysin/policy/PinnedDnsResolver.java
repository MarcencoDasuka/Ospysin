package com.ospysin.policy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Objects;

public class PinnedDnsResolver implements DnsResolver {

    private final String expectedHost;
    private final InetAddress pinnedAddress;

    public PinnedDnsResolver(String expectedHost, InetAddress pinnedAddress) {
        this.expectedHost = Objects.requireNonNull(expectedHost, "expectedHost must not be null")
                .toLowerCase(Locale.ROOT)
                .trim();
        this.pinnedAddress = Objects.requireNonNull(pinnedAddress, "pinnedAddress must not be null");
    }

    public PinnedDnsResolver(InetAddress pinnedAddress) {
        this.expectedHost = null;
        this.pinnedAddress = Objects.requireNonNull(pinnedAddress, "pinnedAddress must not be null");
    }

    @Override
    public InetAddress[] resolveAll(String host) throws UnknownHostException {
        if (expectedHost != null) {
            String normalizedHost = host != null ? host.toLowerCase(Locale.ROOT).trim() : "";
            if (!expectedHost.equalsIgnoreCase(normalizedHost)) {
                throw new UnknownHostException("Host '" + host + "' does not match pinned host '" + expectedHost + "'");
            }
        }
        return new InetAddress[]{pinnedAddress};
    }

    public String getExpectedHost() {
        return expectedHost;
    }

    public InetAddress getPinnedAddress() {
        return pinnedAddress;
    }
}
