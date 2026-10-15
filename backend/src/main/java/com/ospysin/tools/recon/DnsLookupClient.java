package com.ospysin.tools.recon;

import java.util.List;

/**
 * Pluggable SPI contract for DNS record resolution.
 */
public interface DnsLookupClient {

    /**
     * Queries DNS resource records for a domain and record type.
     *
     * @param domain the target domain or host
     * @param recordType the DNS record type (e.g., "A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "SOA", "PTR")
     * @return list of formatted record strings, or an empty list if none found
     * @throws Exception if resolution encounters an unrecoverable failure
     */
    List<String> queryRecords(String domain, String recordType) throws Exception;
}
