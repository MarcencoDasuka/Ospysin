package com.ospysin.tools.recon;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

/**
 * Socket connector SPI allowing deterministic socket mocking for offline tests.
 */
@FunctionalInterface
public interface WhoisSocketConnector {

    /**
     * Connects a socket to the pre-pinned address and port.
     *
     * @param address the pinned target InetAddress
     * @param port the destination port
     * @param timeoutMs connection timeout in milliseconds
     * @return the connected socket
     * @throws IOException if connection fails
     */
    Socket connect(InetAddress address, int port, int timeoutMs) throws IOException;
}
