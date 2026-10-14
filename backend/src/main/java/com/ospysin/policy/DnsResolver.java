package com.ospysin.policy;

import java.net.InetAddress;
import java.net.UnknownHostException;

@FunctionalInterface
public interface DnsResolver {

    InetAddress[] resolveAll(String host) throws UnknownHostException;
}
