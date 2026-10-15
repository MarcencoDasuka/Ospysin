package com.ospysin.tools.recon;

/**
 * Pluggable SPI contract for querying authoritative WHOIS and RDAP directories.
 */
public interface WhoisQueryClient {

    /**
     * Queries authoritative registration directories for the given domain or IP.
     *
     * @param domainOrIp the target domain name or IP address
     * @param maxReferralDepth maximum number of referral hops to follow (0..3)
     * @return the raw and extracted registration record
     * @throws Exception if resolution or transport fails
     */
    WhoisRawResult query(String domainOrIp, int maxReferralDepth) throws Exception;
}
