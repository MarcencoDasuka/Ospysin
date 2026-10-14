package com.ospysin.policy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

public final class CidrBlock {

    private final String cidr;
    private final String description;
    private final byte[] networkBytes;
    private final int prefixLength;

    public CidrBlock(String cidr, String description) {
        this.cidr = Objects.requireNonNull(cidr, "cidr must not be null").trim();
        this.description = Objects.requireNonNull(description, "description must not be null").trim();

        int slashIndex = this.cidr.indexOf('/');
        if (slashIndex <= 0 || slashIndex == this.cidr.length() - 1) {
            throw new IllegalArgumentException("Invalid CIDR notation: " + cidr);
        }

        String ipPart = this.cidr.substring(0, slashIndex);
        int prefix = Integer.parseInt(this.cidr.substring(slashIndex + 1));

        try {
            InetAddress netAddr = InetAddress.getByName(ipPart);
            this.networkBytes = netAddr.getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid network IP in CIDR: " + ipPart, e);
        }

        int maxBits = this.networkBytes.length * 8;
        if (prefix < 0 || prefix > maxBits) {
            throw new IllegalArgumentException("Invalid prefix length " + prefix + " for " + maxBits + "-bit address");
        }
        this.prefixLength = prefix;
    }

    public boolean matches(InetAddress address) {
        if (address == null) {
            return false;
        }
        byte[] targetBytes = address.getAddress();
        if (targetBytes.length != networkBytes.length) {
            return false;
        }

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++) {
            if (targetBytes[i] != networkBytes[i]) {
                return false;
            }
        }

        if (remainingBits > 0) {
            int mask = (0xFF << (8 - remainingBits)) & 0xFF;
            if ((targetBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) {
                return false;
            }
        }

        return true;
    }

    public String getCidr() {
        return cidr;
    }

    public String getDescription() {
        return description;
    }

    public int getPrefixLength() {
        return prefixLength;
    }

    @Override
    public String toString() {
        return cidr + " (" + description + ")";
    }
}
