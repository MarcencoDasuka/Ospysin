package com.ospysin.tools.probes;

import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.policy.io.BoundedResponseStream;
import com.ospysin.policy.io.PayloadLimitGuard;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * SSRF-safe, IP-pinned HTTP transport client for direct target probes.
 * Pins connections directly to pre-validated IP addresses, sets RFC 6066 SNI,
 * enforces Tier 1 and Tier 2 payload bounds through PayloadLimitGuard,
 * and delegates all redirect hops through PolicyEngine.
 */
@Component
public class PinnedHttpClient {

    private static final Logger log = LoggerFactory.getLogger(PinnedHttpClient.class);

    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 5000;
    public static final int DEFAULT_READ_TIMEOUT_MS = 10000;
    public static final int MAX_HEADER_BYTES = 64 * 1024; // 64 KB Tier 1 header cap

    private final PolicyEngine policyEngine;
    private final SSLSocketFactory permissiveSslSocketFactory;

    @Autowired
    public PinnedHttpClient(PolicyEngine policyEngine) {
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.permissiveSslSocketFactory = createPermissiveSslSocketFactory();
    }

    /**
     * Executes an HTTP GET probe against a target URI with default 64 KB caps and 10s read timeout.
     */
    public PinnedProbeResult executeWithRedirects(URI initialUri, InetAddress initialIp, boolean followRedirects,
                                                  SessionMode mode, ScopeAsset scopeAsset) throws IOException, PolicyViolationException {
        return executeWithRedirects(initialUri, initialIp, followRedirects, mode, scopeAsset,
                64 * 1024L, 64 * 1024L, DEFAULT_READ_TIMEOUT_MS);
    }

    /**
     * Executes an HTTP GET probe against a target URI, optionally following redirects up to 3 hops
     * with mandatory PolicyEngine revalidation at each hop, parameterized by payload caps and timeouts.
     */
    public PinnedProbeResult executeWithRedirects(URI initialUri, InetAddress initialIp, boolean followRedirects,
                                                  SessionMode mode, ScopeAsset scopeAsset,
                                                  long maxWireBytes, long maxDecompressedBytes,
                                                  int readTimeoutMs) throws IOException, PolicyViolationException {
        URI currentUri = initialUri;
        InetAddress currentIp = initialIp;
        int hopNumber = 0;

        List<Map<String, Object>> redirectChain = new ArrayList<>();
        StringBuilder combinedRawOutput = new StringBuilder();

        while (true) {
            PinnedHttpResponse response = executeSingle(currentUri, currentIp, maxWireBytes, maxDecompressedBytes, readTimeoutMs);

            int status = response.statusCode();
            boolean isRedirect = status == 301 || status == 302 || status == 303 || status == 307 || status == 308;

            if (followRedirects && isRedirect) {
                hopNumber++;
                String location = getFirstHeader(response.headers(), "location");

                if (location == null || location.isBlank()) {
                    // No location header; stop redirect following and return current response
                    appendRawTrace(combinedRawOutput, response.rawStatusAndHeaders());
                    return buildProbeResult(currentUri, response, redirectChain, combinedRawOutput.toString());
                }

                // Policy validation for redirect hop
                PolicyDecision hopDecision = policyEngine.evaluateRedirectHop(currentUri, location, hopNumber, mode, scopeAsset);
                if (!hopDecision.allowed()) {
                    log.warn("Redirect hop {} to '{}' denied by policy: {}", hopNumber, location, hopDecision.reason());
                    throw new PolicyViolationException(
                            "Policy violation on redirect hop " + hopNumber + ": " + hopDecision.reason(),
                            List.of(new InvalidParam("redirect", hopDecision.reason()))
                    );
                }

                URI nextUri = currentUri.resolve(location.trim());
                InetAddress nextIp = hopDecision.resolvedIp();

                redirectChain.add(Map.of(
                        "hop", hopNumber,
                        "fromUrl", currentUri.toString(),
                        "toUrl", nextUri.toString(),
                        "statusCode", status
                ));

                combinedRawOutput.append("--- Redirect Hop ").append(hopNumber).append(" (HTTP ").append(status).append(") ---\n")
                        .append(response.rawStatusAndHeaders()).append("\n\n");

                currentUri = nextUri;
                currentIp = nextIp;
            } else {
                if (redirectChain.isEmpty()) {
                    combinedRawOutput.append(response.rawStatusAndHeaders());
                } else {
                    combinedRawOutput.append("--- Final Response (HTTP ").append(status).append(") ---\n")
                            .append(response.rawStatusAndHeaders());
                }
                return buildProbeResult(currentUri, response, redirectChain, combinedRawOutput.toString());
            }
        }
    }

    /**
     * Executes a single IP-pinned HTTP GET request without following redirects, using default caps and timeouts.
     */
    public PinnedHttpResponse executeSingle(URI uri, InetAddress pinnedIp) throws IOException {
        return executeSingle(uri, pinnedIp, 64 * 1024L, 64 * 1024L, DEFAULT_READ_TIMEOUT_MS);
    }

    /**
     * Executes a single IP-pinned HTTP GET request without following redirects, with custom bounds.
     */
    public PinnedHttpResponse executeSingle(URI uri, InetAddress pinnedIp,
                                            long maxWireBytes, long maxDecompressedBytes,
                                            int readTimeoutMs) throws IOException {
        try {
            boolean is5ArgOverridden = getClass().getMethod("executeSingle", URI.class, InetAddress.class, long.class, long.class, int.class)
                    .getDeclaringClass() != PinnedHttpClient.class;
            boolean is2ArgOverridden = getClass().getMethod("executeSingle", URI.class, InetAddress.class)
                    .getDeclaringClass() != PinnedHttpClient.class;
            if (!is5ArgOverridden && is2ArgOverridden) {
                return executeSingle(uri, pinnedIp);
            }
        } catch (NoSuchMethodException ignored) {
        }

        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "http";
        boolean isHttps = "https".equals(scheme);

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            host = extractHostFromAuthority(uri.getRawAuthority());
        }

        int port = uri.getPort();
        if (port == -1) {
            port = isHttps ? 443 : 80;
        }

        Socket rawSocket = new Socket();
        try {
            rawSocket.connect(new InetSocketAddress(pinnedIp, port), DEFAULT_CONNECT_TIMEOUT_MS);
            rawSocket.setSoTimeout(readTimeoutMs);

            Socket activeSocket = rawSocket;
            if (isHttps) {
                SSLSocket sslSocket = (SSLSocket) permissiveSslSocketFactory.createSocket(rawSocket, host, port, true);
                SSLParameters sslParams = sslSocket.getSSLParameters();
                if (!isIpLiteral(host)) {
                    sslParams.setServerNames(List.of(new SNIHostName(host)));
                }
                sslSocket.setSSLParameters(sslParams);
                sslSocket.startHandshake();
                activeSocket = sslSocket;
            }

            // Construct HTTP/1.1 request
            String path = uri.getRawPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            if (uri.getRawQuery() != null && !uri.getRawQuery().isBlank()) {
                path += "?" + uri.getRawQuery();
            }

            String formattedHost = host;
            if (host.contains(":") && !host.startsWith("[")) {
                formattedHost = "[" + host + "]";
            }
            String hostHeader = formattedHost;
            if ((!isHttps && port != 80) || (isHttps && port != 443)) {
                hostHeader = formattedHost + ":" + port;
            }

            String request = "GET " + path + " HTTP/1.1\r\n"
                    + "Host: " + hostHeader + "\r\n"
                    + "User-Agent: Ospysin-Audit/1.0\r\n"
                    + "Accept: */*\r\n"
                    + "Accept-Encoding: gzip\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";

            OutputStream out = activeSocket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            // Read response status and headers
            InputStream in = activeSocket.getInputStream();
            return parseHttpResponse(uri, in, maxWireBytes, maxDecompressedBytes);
        } finally {
            try {
                rawSocket.close();
            } catch (Exception ignored) {
            }
        }
    }

    private PinnedHttpResponse parseHttpResponse(URI requestUri, InputStream in,
                                                 long maxWireBytes, long maxDecompressedBytes) throws IOException {
        List<String> rawHeaderLines = new ArrayList<>();
        ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream();
        int totalHeaderBytes = 0;
        int prev = -1;
        int curr;

        while ((curr = in.read()) != -1) {
            totalHeaderBytes++;
            if (totalHeaderBytes > MAX_HEADER_BYTES) {
                throw new IOException("HTTP response headers exceeded maximum allowed size of 64 KB");
            }
            if (curr == '\n' && prev == '\r') {
                byte[] bytes = lineBuffer.toByteArray();
                String line = new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.UTF_8);
                if (line.isEmpty()) {
                    break;
                }
                rawHeaderLines.add(line);
                lineBuffer.reset();
            } else {
                lineBuffer.write(curr);
            }
            prev = curr;
        }

        if (rawHeaderLines.isEmpty()) {
            throw new IOException("Premature EOF: Server closed connection without returning HTTP status line");
        }

        String statusLine = rawHeaderLines.get(0);
        String httpVersion = "HTTP/1.1";
        int statusCode = 200;
        String reasonPhrase = "";

        String[] statusParts = statusLine.split("\\s+", 3);
        if (statusParts.length >= 2) {
            httpVersion = statusParts[0];
            try {
                statusCode = Integer.parseInt(statusParts[1]);
            } catch (NumberFormatException ignored) {
            }
            if (statusParts.length >= 3) {
                reasonPhrase = statusParts[2];
            }
        }

        Map<String, List<String>> headers = new LinkedHashMap<>();
        List<ParsedCookie> cookies = new ArrayList<>();

        for (int i = 1; i < rawHeaderLines.size(); i++) {
            String line = rawHeaderLines.get(i);
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String name = line.substring(0, colonIdx).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(colonIdx + 1).trim();
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);

                if ("set-cookie".equals(name)) {
                    ParsedCookie cookie = CookieParser.parse(value);
                    if (cookie != null) {
                        cookies.add(cookie);
                    }
                }
            }
        }

        // Body reading decision:
        // Skip body for 1xx, 204, 304, redirects (301, 302, 303, 307, 308), or Content-Length: 0 (P10-02)
        boolean isRedirect = statusCode == 301 || statusCode == 302 || statusCode == 303
                || statusCode == 307 || statusCode == 308;
        boolean hasNoBodyStatus = (statusCode >= 100 && statusCode < 200) || statusCode == 204
                || statusCode == 304 || isRedirect;

        long contentLength = -1;
        String clHeader = getFirstHeader(headers, "content-length");
        if (clHeader != null) {
            try {
                contentLength = Long.parseLong(clHeader.trim());
            } catch (NumberFormatException ignored) {
            }
        }

        byte[] bodyBytes = new byte[0];
        if (!hasNoBodyStatus && contentLength != 0) {
            boolean isChunked = headers.getOrDefault("transfer-encoding", List.of())
                    .stream()
                    .anyMatch(v -> v.toLowerCase(Locale.ROOT).contains("chunked"));

            InputStream bodyStream = in;
            if (isChunked) {
                bodyStream = new ChunkedInputStream(in, maxWireBytes);
            } else if (contentLength > 0) {
                bodyStream = new FixedLengthInputStream(in, contentLength);
            }

            boolean isGzip = headers.getOrDefault("content-encoding", List.of())
                    .stream()
                    .anyMatch(v -> v.toLowerCase(Locale.ROOT).contains("gzip"));

            ByteArrayOutputStream bodyCapture = new ByteArrayOutputStream();
            try (BoundedResponseStream boundedStream = PayloadLimitGuard.wrap(bodyStream, maxWireBytes, maxDecompressedBytes, isGzip)) {
                byte[] buf = new byte[8192];
                int read;
                int captureCap = (int) Math.min(maxDecompressedBytes, Integer.MAX_VALUE);
                while ((read = boundedStream.read(buf)) != -1) {
                    if (bodyCapture.size() < captureCap) {
                        bodyCapture.write(buf, 0, Math.min(read, captureCap - bodyCapture.size()));
                    }
                }
                bodyBytes = bodyCapture.toByteArray();
            } catch (EOFException | java.util.zip.ZipException e) {
                // Gracefully handle EOF or zip errors on empty/truncated gzip streams
                log.debug("EOF/ZipException while reading or decompressing HTTP body: {}", e.getMessage());
                bodyBytes = bodyCapture.toByteArray();
            }
        }

        String rawStatusAndHeaders = String.join("\r\n", rawHeaderLines);
        return new PinnedHttpResponse(
                requestUri,
                statusCode,
                httpVersion,
                reasonPhrase,
                headers,
                cookies,
                rawStatusAndHeaders,
                bodyBytes
        );
    }

    private PinnedProbeResult buildProbeResult(URI finalUri, PinnedHttpResponse response,
                                               List<Map<String, Object>> redirectChain, String rawOutput) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : response.headers().entrySet()) {
            if ("set-cookie".equals(entry.getKey())) {
                continue;
            }
            normalized.put(entry.getKey(), String.join(", ", entry.getValue()));
        }

        return new PinnedProbeResult(
                finalUri.toString(),
                response.statusCode(),
                response.httpVersion(),
                normalized,
                response.cookies(),
                redirectChain,
                rawOutput,
                response.bodyBytes()
        );
    }

    private void appendRawTrace(StringBuilder sb, String trace) {
        if (!sb.isEmpty()) {
            sb.append("\n\n");
        }
        sb.append(trace);
    }

    private String getFirstHeader(Map<String, List<String>> headers, String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        if (values != null && !values.isEmpty()) {
            return values.get(0);
        }
        return null;
    }

    private String extractHostFromAuthority(String authority) {
        if (authority == null || authority.isBlank()) {
            return "";
        }
        int at = authority.indexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        int lastBracket = authority.lastIndexOf(']');
        if (lastBracket >= 0) {
            int colonAfterBracket = authority.indexOf(':', lastBracket);
            if (colonAfterBracket > 0) {
                authority = authority.substring(0, colonAfterBracket);
            }
        } else {
            int firstColon = authority.indexOf(':');
            int lastColon = authority.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon) {
                authority = authority.substring(0, firstColon);
            }
        }
        if (authority.startsWith("[") && authority.endsWith("]")) {
            authority = authority.substring(1, authority.length() - 1);
        }
        return authority;
    }

    private boolean isIpLiteral(String host) {
        return ObfuscatedIpParser.parse(host) != null;
    }

    private SSLSocketFactory createPermissiveSslSocketFactory() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new PermissiveTrustManager()}, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize permissive SSL context for HTTP probes", e);
        }
    }

    private static class PermissiveTrustManager extends X509ExtendedTrustManager {
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class FixedLengthInputStream extends InputStream {
        private final InputStream in;
        private long remaining;

        public FixedLengthInputStream(InputStream in, long length) {
            this.in = in;
            this.remaining = length;
        }

        @Override
        public int read() throws IOException {
            if (remaining <= 0) return -1;
            int b = in.read();
            if (b != -1) remaining--;
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) return -1;
            int toRead = (int) Math.min(len, remaining);
            int read = in.read(b, off, toRead);
            if (read != -1) remaining -= read;
            return read;
        }
    }

    static class ChunkedInputStream extends InputStream {
        private final InputStream in;
        private long remainingInChunk = 0;
        private boolean eof = false;
        private long totalWireBytesRead = 0;
        private final long maxWireBytes;

        public ChunkedInputStream(InputStream in) {
            this(in, PayloadLimitGuard.DEFAULT_WIRE_CAP);
        }

        public ChunkedInputStream(InputStream in, long maxWireBytes) {
            this.in = in;
            this.maxWireBytes = maxWireBytes;
        }

        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            int r = read(b, 0, 1);
            return r == -1 ? -1 : (b[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (eof) {
                return -1;
            }
            if (remainingInChunk == 0) {
                readChunkHeader();
                if (eof) {
                    return -1;
                }
            }
            int toRead = (int) Math.min(len, remainingInChunk);
            int bytesRead = in.read(b, off, toRead);
            if (bytesRead == -1) {
                eof = true;
                return -1;
            }
            trackWireBytes(bytesRead);
            remainingInChunk -= bytesRead;
            if (remainingInChunk == 0) {
                readCrLf();
            }
            return bytesRead;
        }

        private void readChunkHeader() throws IOException {
            String line = readLine();
            if (line == null) {
                eof = true;
                return;
            }
            int semi = line.indexOf(';');
            if (semi >= 0) {
                line = line.substring(0, semi);
            }
            line = line.trim();
            if (line.isEmpty()) {
                eof = true;
                return;
            }
            try {
                remainingInChunk = Long.parseLong(line, 16);
            } catch (NumberFormatException e) {
                throw new IOException("Invalid chunk size in chunked encoding: " + line, e);
            }
            if (remainingInChunk < 0) {
                throw new IOException("Negative chunk size in chunked encoding: " + remainingInChunk);
            }
            if (remainingInChunk == 0) {
                eof = true;
                while (true) {
                    String trailer = readLine();
                    if (trailer == null || trailer.isEmpty()) {
                        break;
                    }
                }
            }
        }

        private void readCrLf() throws IOException {
            int c1 = in.read();
            if (c1 == -1) return;
            trackWireBytes(1);
            if (c1 == '\r') {
                int c2 = in.read();
                if (c2 == -1) return;
                trackWireBytes(1);
                if (c2 != '\n') {
                    throw new IOException("Malformed chunk delimiter: expected LF after CR");
                }
            } else if (c1 != '\n') {
                throw new IOException("Malformed chunk delimiter: expected CRLF");
            }
        }

        private String readLine() throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int prev = -1;
            int curr;
            while ((curr = in.read()) != -1) {
                trackWireBytes(1);
                if (curr == '\n' && prev == '\r') {
                    byte[] bytes = baos.toByteArray();
                    return new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.US_ASCII);
                }
                baos.write(curr);
                prev = curr;
            }
            if (baos.size() == 0) {
                return null;
            }
            return baos.toString(StandardCharsets.US_ASCII);
        }

        private void trackWireBytes(long count) throws IOException {
            totalWireBytesRead += count;
            if (totalWireBytesRead > maxWireBytes) {
                throw new IOException("Chunked stream exceeded maximum wire cap of " + maxWireBytes + " bytes");
            }
        }
    }
}
