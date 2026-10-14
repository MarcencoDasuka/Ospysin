package com.ospysin.policy;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Component
public class SystemDnsResolver implements DnsResolver {

    @Override
    public InetAddress[] resolveAll(String host) throws UnknownHostException {
        return InetAddress.getAllByName(host);
    }
}
