package com.ospysin.tools.recon;

import com.ospysin.policy.ObfuscatedIpParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Standard DnsLookupClient implementation powered by dnsjava (org.xbill.DNS).
 */
@Slf4j
@Component
public class DnsjavaLookupClient implements DnsLookupClient {

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private final Resolver customResolver;

    public DnsjavaLookupClient() {
        this(null);
    }

    public DnsjavaLookupClient(Resolver customResolver) {
        this.customResolver = customResolver;
    }

    @Override
    public List<String> queryRecords(String domain, String recordType) throws Exception {
        if (domain == null || domain.isBlank() || recordType == null || recordType.isBlank()) {
            return Collections.emptyList();
        }

        String normalizedDomain = domain.trim();
        String normalizedType = recordType.trim().toUpperCase(Locale.ROOT);
        int typeValue = Type.value(normalizedType);
        if (typeValue < 0) {
            log.debug("Unknown DNS record type: {}", recordType);
            return Collections.emptyList();
        }

        Name queryName;
        if ("PTR".equalsIgnoreCase(normalizedType)) {
            InetAddress ip = ObfuscatedIpParser.parse(normalizedDomain);
            if (ip != null) {
                queryName = ReverseMap.fromAddress(ip);
            } else {
                try {
                    queryName = ReverseMap.fromAddress(normalizedDomain);
                } catch (UnknownHostException e) {
                    try {
                        String fqdn = normalizedDomain.endsWith(".") ? normalizedDomain : normalizedDomain + ".";
                        queryName = Name.fromString(fqdn);
                    } catch (TextParseException tpe) {
                        return Collections.emptyList();
                    }
                }
            }
        } else {
            try {
                String fqdn = normalizedDomain.endsWith(".") ? normalizedDomain : normalizedDomain + ".";
                queryName = Name.fromString(fqdn);
            } catch (TextParseException e) {
                log.debug("Malformed domain name '{}': {}", normalizedDomain, e.getMessage());
                return Collections.emptyList();
            }
        }

        Lookup lookup = new Lookup(queryName, typeValue);
        if (this.customResolver != null) {
            lookup.setResolver(this.customResolver);
        } else {
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(DEFAULT_TIMEOUT);
            lookup.setResolver(resolver);
        }

        Record[] records = lookup.run();
        if (records == null || records.length == 0) {
            return Collections.emptyList();
        }

        List<String> results = new ArrayList<>();
        for (Record record : records) {
            String formatted = formatRecord(record);
            if (formatted != null && !formatted.isBlank()) {
                results.add(formatted);
            }
        }
        return Collections.unmodifiableList(results);
    }

    private String formatRecord(Record record) {
        if (record instanceof ARecord a) {
            return a.getAddress().getHostAddress();
        } else if (record instanceof AAAARecord aaaa) {
            return aaaa.getAddress().getHostAddress();
        } else if (record instanceof MXRecord mx) {
            return mx.getPriority() + " " + mx.getTarget().toString();
        } else if (record instanceof TXTRecord txt) {
            return String.join("", txt.getStrings());
        } else if (record instanceof CNAMERecord cname) {
            return cname.getTarget().toString();
        } else if (record instanceof NSRecord ns) {
            return ns.getTarget().toString();
        } else if (record instanceof PTRRecord ptr) {
            return ptr.getTarget().toString();
        } else if (record instanceof SOARecord soa) {
            return soa.rdataToString();
        } else if (record instanceof CAARecord caa) {
            return caa.rdataToString();
        } else {
            return record.rdataToString();
        }
    }
}
