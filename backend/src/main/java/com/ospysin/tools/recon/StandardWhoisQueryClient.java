package com.ospysin.tools.recon;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ospysin.policy.DnsResolver;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.policy.io.PayloadLimitGuard;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Standard WhoisQueryClient performing RDAP queries with fallback to RFC 3912 port 43 WHOIS.
 * Enforces strict SSRF defense, DNS pre-flight verification, IP pinning, referral loop protection,
 * 32 KB payload bounds, and registrant PII redaction.
 */
@Slf4j
@Component
public class StandardWhoisQueryClient implements WhoisQueryClient {

    public static final int CONNECT_TIMEOUT_MS = 5000;
    public static final int READ_TIMEOUT_MS = 15000;
    public static final long PAYLOAD_CAP_BYTES = 32 * 1024L; // 32 KB
    public static final int MAX_REDIRECT_HOPS = 3;

    private static final Pattern REFERRAL_LINE_PATTERN = Pattern.compile(
            "(?im)^\\s*(?:refer|Registrar WHOIS Server|ReferralServer|whois):\\s*(?:[a-z]+://)?([^\\s\\r\\n/:]+)(?::(\\d+))?"
    );

    private static final Pattern REGISTRAR_PATTERN = Pattern.compile(
            "(?im)^\\s*(?:Registrar|Registrar Name|Sponsoring Registrar):\\s*(.+)$"
    );

    private static final Pattern CREATION_DATE_PATTERN = Pattern.compile(
            "(?im)^\\s*(?:Creation Date|Created On|Registration Time|Created):\\s*(.+)$"
    );

    private static final Pattern EXPIRATION_DATE_PATTERN = Pattern.compile(
            "(?im)^\\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expires On|Expires):\\s*(.+)$"
    );

    private static final Pattern NAMESERVER_PATTERN = Pattern.compile(
            "(?im)^\\s*(?:Name Server|nserver):\\s*([^\r\n\\s]+)"
    );

    private static final Pattern STATUS_PATTERN = Pattern.compile(
            "(?im)^\\s*(?:Domain Status|Status):\\s*([^\r\n\\s]+)"
    );

    private final DnsResolver dnsResolver;
    private final IpRangeValidator ipRangeValidator;
    private final ObjectMapper objectMapper;
    private final String rdapBaseUrl;
    private final String whoisRootServer;
    private final int whoisPort;

    private WhoisSocketConnector socketConnector = (address, port, timeoutMs) -> {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(address, port), timeoutMs);
        return socket;
    };

    private SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

    @Autowired
    public StandardWhoisQueryClient(
            DnsResolver dnsResolver,
            IpRangeValidator ipRangeValidator,
            ObjectMapper objectMapper,
            @Value("${ospysin.whois.rdap-base-url:https://rdap.org/domain/}") String rdapBaseUrl,
            @Value("${ospysin.whois.root-server:whois.iana.org}") String whoisRootServer,
            @Value("${ospysin.whois.port:43}") int whoisPort
    ) {
        this.dnsResolver = Objects.requireNonNull(dnsResolver, "dnsResolver must not be null");
        this.ipRangeValidator = Objects.requireNonNull(ipRangeValidator, "ipRangeValidator must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.rdapBaseUrl = rdapBaseUrl != null && !rdapBaseUrl.isBlank() ? rdapBaseUrl.trim() : "https://rdap.org/domain/";
        this.whoisRootServer = whoisRootServer != null && !whoisRootServer.isBlank() ? whoisRootServer.trim() : "whois.iana.org";
        this.whoisPort = whoisPort > 0 ? whoisPort : 43;
    }

    public void setSocketConnector(WhoisSocketConnector socketConnector) {
        this.socketConnector = Objects.requireNonNull(socketConnector, "socketConnector must not be null");
    }

    public void setSslSocketFactory(SSLSocketFactory sslSocketFactory) {
        this.sslSocketFactory = Objects.requireNonNull(sslSocketFactory, "sslSocketFactory must not be null");
    }

    @Override
    public WhoisRawResult query(String domainOrIp, int maxReferralDepth) throws Exception {
        if (domainOrIp == null || domainOrIp.isBlank()) {
            throw new IllegalArgumentException("domainOrIp must not be blank");
        }

        String target = domainOrIp.trim();
        int effectiveDepth = Math.max(0, Math.min(maxReferralDepth, 3));

        // 1. Attempt RDAP JSON lookup first
        try {
            WhoisRawResult rdapResult = queryRdap(target);
            if (rdapResult != null) {
                return rdapResult;
            }
        } catch (PolicyViolationException pve) {
            // Policy violations must never be swallowed by falling back to port 43!
            throw pve;
        } catch (Exception ex) {
            log.debug("RDAP query failed for '{}', falling back to WHOIS port 43: {}", target, ex.getMessage());
        }

        // 2. Fall back to RFC 3912 WHOIS port 43 with referral following
        return queryPort43(target, effectiveDepth);
    }

    private WhoisRawResult queryRdap(String domainOrIp) throws Exception {
        boolean isIp = ObfuscatedIpParser.parse(domainOrIp) != null;
        String endpointUrl;
        if (isIp && this.rdapBaseUrl.contains("/domain/")) {
            endpointUrl = this.rdapBaseUrl.replace("/domain/", "/ip/") + domainOrIp;
        } else {
            endpointUrl = this.rdapBaseUrl.endsWith("/") ? this.rdapBaseUrl + domainOrIp : this.rdapBaseUrl + "/" + domainOrIp;
        }

        int configuredRdapPort = -1;
        try {
            configuredRdapPort = URI.create(this.rdapBaseUrl).getPort();
        } catch (Exception ignored) {
        }

        URI currentUri = URI.create(endpointUrl);
        int redirectHops = 0;

        while (true) {
            String scheme = currentUri.getScheme();
            if (scheme == null || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
                throw new PolicyViolationException("Prohibited RDAP URL scheme: " + scheme,
                        List.of(new InvalidParam("rdapUrl", "Only http and https schemes are allowed")));
            }

            String host = currentUri.getHost();
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Invalid RDAP URI host: " + currentUri);
            }

            int port = currentUri.getPort();
            boolean isHttps = "https".equalsIgnoreCase(scheme);
            if (port == -1) {
                port = isHttps ? 443 : 80;
            }

            if (port != 80 && port != 443 && (configuredRdapPort == -1 || port != configuredRdapPort)) {
                throw new PolicyViolationException("Prohibited RDAP port: " + port,
                        List.of(new InvalidParam("rdapPort", "Disallowed RDAP port: " + port)));
            }

            // SSRF Guard: resolve & validate against PUBLIC mode
            InetAddress pinnedIp = resolveAndValidatePublic(host);

            Socket rawSocket = socketConnector.connect(pinnedIp, port, CONNECT_TIMEOUT_MS);
            rawSocket.setSoTimeout(READ_TIMEOUT_MS);
            Socket activeSocket = rawSocket;

            try {
                if (isHttps) {
                    SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(rawSocket, host, port, true);
                    SSLParameters params = sslSocket.getSSLParameters();
                    if (ObfuscatedIpParser.parse(host) == null) {
                        params.setServerNames(List.of(new SNIHostName(host)));
                    }
                    params.setEndpointIdentificationAlgorithm("HTTPS");
                    sslSocket.setSSLParameters(params);
                    sslSocket.startHandshake();
                    activeSocket = sslSocket;
                }

                String path = currentUri.getRawPath() != null && !currentUri.getRawPath().isBlank() ? currentUri.getRawPath() : "/";
                if (currentUri.getRawQuery() != null && !currentUri.getRawQuery().isBlank()) {
                    path += "?" + currentUri.getRawQuery();
                }

                String hostHeader = host + ((isHttps && port != 443) || (!isHttps && port != 80) ? ":" + port : "");
                String request = "GET " + path + " HTTP/1.1\r\n"
                        + "Host: " + hostHeader + "\r\n"
                        + "Accept: application/rdap+json, application/json\r\n"
                        + "User-Agent: Ospysin-Audit/1.0\r\n"
                        + "Connection: close\r\n\r\n";

                OutputStream out = activeSocket.getOutputStream();
                out.write(request.getBytes(StandardCharsets.US_ASCII));
                out.flush();

                InputStream in = activeSocket.getInputStream();
                RdapHttpResponse response = readHttpResponse(in);

                if (response.statusCode() == 200) {
                    return parseRdapResponse(response.body(), currentUri.toString());
                } else if (response.statusCode() == 301 || response.statusCode() == 302 || response.statusCode() == 303 || response.statusCode() == 307 || response.statusCode() == 308) {
                    redirectHops++;
                    if (redirectHops > MAX_REDIRECT_HOPS) {
                        log.debug("RDAP redirect hop limit ({}) exceeded", MAX_REDIRECT_HOPS);
                        return null;
                    }
                    String location = response.getHeader("Location");
                    if (location == null || location.isBlank()) {
                        return null;
                    }
                    currentUri = currentUri.resolve(location.trim());
                } else {
                    log.debug("RDAP responded with HTTP status {}", response.statusCode());
                    return null;
                }
            } finally {
                try {
                    activeSocket.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private WhoisRawResult parseRdapResponse(String jsonBody, String rdapUrl) {
        try {
            JsonNode root = objectMapper.readTree(jsonBody);

            String registrar = "Unknown";
            JsonNode entities = root.path("entities");
            if (entities.isArray()) {
                for (JsonNode entity : entities) {
                    JsonNode roles = entity.path("roles");
                    boolean isRegistrar = false;
                    if (roles.isArray()) {
                        for (JsonNode r : roles) {
                            if ("registrar".equalsIgnoreCase(r.asText())) {
                                isRegistrar = true;
                                break;
                            }
                        }
                    }
                    if (isRegistrar) {
                        String fn = extractVcardFn(entity.path("vcardArray"));
                        if (fn != null && !fn.isBlank()) {
                            registrar = fn;
                            break;
                        } else if (entity.hasNonNull("handle")) {
                            registrar = entity.path("handle").asText();
                            break;
                        }
                    }
                }
            }

            String createdDate = null;
            String expiresDate = null;
            JsonNode events = root.path("events");
            if (events.isArray()) {
                for (JsonNode ev : events) {
                    String action = ev.path("eventAction").asText();
                    String date = ev.path("eventDate").asText();
                    if ("registration".equalsIgnoreCase(action)) {
                        createdDate = normalizeDate(date);
                    } else if ("expiration".equalsIgnoreCase(action)) {
                        expiresDate = normalizeDate(date);
                    }
                }
            }

            List<String> nameServers = new ArrayList<>();
            JsonNode nameservers = root.path("nameservers");
            if (nameservers.isArray()) {
                for (JsonNode ns : nameservers) {
                    String ldhName = ns.path("ldhName").asText();
                    if (ldhName != null && !ldhName.isBlank()) {
                        nameServers.add(ldhName.toLowerCase(Locale.ROOT));
                    }
                }
            }

            List<String> statuses = new ArrayList<>();
            JsonNode statusNode = root.path("status");
            if (statusNode.isArray()) {
                for (JsonNode st : statusNode) {
                    String s = st.asText();
                    if (s != null && !s.isBlank()) {
                        statuses.add(s.trim());
                    }
                }
            }

            String redactedJson = redactPii(jsonBody);
            return new WhoisRawResult(
                    redactedJson,
                    registrar,
                    createdDate,
                    expiresDate,
                    nameServers,
                    statuses,
                    "RDAP",
                    List.of(rdapUrl)
            );
        } catch (Exception ex) {
            log.debug("Failed to parse RDAP JSON response: {}", ex.getMessage());
            return null;
        }
    }

    private String extractVcardFn(JsonNode vcardArray) {
        if (vcardArray == null || !vcardArray.isArray() || vcardArray.size() < 2) {
            return null;
        }
        JsonNode properties = vcardArray.get(1);
        if (properties.isArray()) {
            for (JsonNode prop : properties) {
                if (prop.isArray() && prop.size() >= 4) {
                    String propName = prop.get(0).asText();
                    if ("fn".equalsIgnoreCase(propName)) {
                        return prop.get(3).asText();
                    }
                }
            }
        }
        return null;
    }

    private WhoisRawResult queryPort43(String domainOrIp, int maxReferralDepth) throws Exception {
        String currentServer = this.whoisRootServer;
        int currentPort = this.whoisPort;
        int depth = 0;

        Set<String> visitedServers = new LinkedHashSet<>();
        List<String> referralChain = new ArrayList<>();
        String finalRawOutput = "";

        while (depth <= maxReferralDepth) {
            String normalizedServer = normalizeServer(currentServer);
            String serverKey = normalizedServer.toLowerCase(Locale.ROOT);

            if (visitedServers.contains(serverKey)) {
                log.debug("WHOIS referral loop detected for server '{}'. Stopping referrals.", normalizedServer);
                break;
            }
            visitedServers.add(serverKey);
            referralChain.add(normalizedServer);

            // SSRF Guard: resolve & validate against PUBLIC mode
            InetAddress pinnedIp = resolveAndValidatePublic(normalizedServer);

            String rawText;
            try (Socket socket = socketConnector.connect(pinnedIp, currentPort, CONNECT_TIMEOUT_MS)) {
                socket.setSoTimeout(READ_TIMEOUT_MS);

                OutputStream out = socket.getOutputStream();
                out.write((domainOrIp + "\r\n").getBytes(StandardCharsets.UTF_8));
                out.flush();

                try (InputStream in = PayloadLimitGuard.wrap(socket.getInputStream(), PAYLOAD_CAP_BYTES, PAYLOAD_CAP_BYTES, false)) {
                    rawText = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                }
            }

            finalRawOutput = rawText;

            // Check for referral server
            String nextServer = extractReferralServer(rawText);
            if (nextServer != null && !visitedServers.contains(nextServer.toLowerCase(Locale.ROOT)) && depth < maxReferralDepth) {
                currentServer = nextServer;
                depth++;
            } else {
                break;
            }
        }

        String redactedOutput = redactPii(finalRawOutput);
        return parseTextWhois(redactedOutput, referralChain);
    }

    private WhoisRawResult parseTextWhois(String rawText, List<String> referralChain) {
        String registrar = "Unknown";
        Matcher regMatcher = REGISTRAR_PATTERN.matcher(rawText);
        if (regMatcher.find()) {
            registrar = regMatcher.group(1).trim();
        }

        String createdDate = null;
        Matcher createMatcher = CREATION_DATE_PATTERN.matcher(rawText);
        if (createMatcher.find()) {
            createdDate = normalizeDate(createMatcher.group(1).trim());
        }

        String expiresDate = null;
        Matcher expMatcher = EXPIRATION_DATE_PATTERN.matcher(rawText);
        if (expMatcher.find()) {
            expiresDate = normalizeDate(expMatcher.group(1).trim());
        }

        Set<String> nameServers = new LinkedHashSet<>();
        Matcher nsMatcher = NAMESERVER_PATTERN.matcher(rawText);
        while (nsMatcher.find()) {
            String ns = nsMatcher.group(1).trim().toLowerCase(Locale.ROOT);
            while (ns.endsWith(".")) {
                ns = ns.substring(0, ns.length() - 1);
            }
            if (!ns.isBlank()) {
                nameServers.add(ns);
            }
        }

        Set<String> statuses = new LinkedHashSet<>();
        Matcher stMatcher = STATUS_PATTERN.matcher(rawText);
        while (stMatcher.find()) {
            String st = stMatcher.group(1).trim();
            int firstSpace = st.indexOf(' ');
            if (firstSpace > 0) {
                st = st.substring(0, firstSpace);
            }
            if (!st.isBlank()) {
                statuses.add(st);
            }
        }

        return new WhoisRawResult(
                rawText,
                registrar,
                createdDate,
                expiresDate,
                new ArrayList<>(nameServers),
                new ArrayList<>(statuses),
                "WHOIS",
                referralChain
        );
    }

    public InetAddress resolveAndValidatePublic(String host) throws UnknownHostException, PolicyViolationException {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Host must not be blank");
        }
        String cleanHost = host.trim();
        if (cleanHost.startsWith("[") && cleanHost.endsWith("]")) {
            cleanHost = cleanHost.substring(1, cleanHost.length() - 1);
        }

        InetAddress[] addresses = dnsResolver.resolveAll(cleanHost);
        if (addresses == null || addresses.length == 0) {
            throw new UnknownHostException("No DNS records resolved for host: " + cleanHost);
        }

        for (InetAddress addr : addresses) {
            Optional<String> denialReason = ipRangeValidator.validate(addr, SessionMode.PUBLIC);
            if (denialReason.isPresent()) {
                throw new PolicyViolationException(
                        "WHOIS/RDAP destination blocked by policy: " + cleanHost + " -> " + addr.getHostAddress() + ": " + denialReason.get(),
                        List.of(new InvalidParam("referralServer", denialReason.get()))
                );
            }
        }

        return addresses[0];
    }

    private String extractReferralServer(String rawText) {
        if (rawText == null || rawText.isBlank()) {
            return null;
        }
        Matcher matcher = REFERRAL_LINE_PATTERN.matcher(rawText);
        if (matcher.find()) {
            String host = matcher.group(1).trim();
            return normalizeServer(host);
        }
        return null;
    }

    private String normalizeServer(String server) {
        String normalized = server.trim();
        if (normalized.startsWith("whois://") || normalized.startsWith("rwhois://")) {
            normalized = normalized.substring(normalized.indexOf("://") + 3);
        }
        int slash = normalized.indexOf('/');
        if (slash >= 0) {
            normalized = normalized.substring(0, slash);
        }
        int colon = normalized.indexOf(':');
        if (colon >= 0) {
            normalized = normalized.substring(0, colon);
        }
        return normalized;
    }

    public static String redactPii(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String result = raw;

        // Line-based text redaction for WHOIS
        result = Pattern.compile("(?im)^(\\s*(?:Registrant|Admin|Administrative|Tech|Technical|Billing)\\s+(?:Street|Address|Phone|Phone Ext|Fax|Fax Ext|Email|Postal Code):\\s*).+$")
                .matcher(result)
                .replaceAll("$1[REDACTED]");

        // JSON key-based redaction for RDAP
        result = Pattern.compile("(?i)(\"(?:email|tel|phone|fax|street|postal-code)\"\\s*:\\s*\")[^\"]+(\")")
                .matcher(result)
                .replaceAll("$1[REDACTED]$2");

        // RDAP vCard array redaction: ["email", {}, "text", "val"]
        result = Pattern.compile("(?i)(\\[\\s*\"(?:email|tel|phone|adr|street)\"\\s*,\\s*\\{[^}]*\\}\\s*,\\s*\"[^\"]*\"\\s*,\\s*\")[^\"]+(\"\\])")
                .matcher(result)
                .replaceAll("$1[REDACTED]$2");

        return result;
    }

    public static String normalizeDate(String rawDate) {
        if (rawDate == null || rawDate.isBlank()) {
            return null;
        }
        String trimmed = rawDate.trim();

        // 1. Direct Instant parse (e.g. 1995-08-14T04:00:00Z)
        try {
            return Instant.parse(trimmed).toString();
        } catch (Exception ignored) {
        }

        // 2. ISO Offset Date Time (e.g. 1995-08-14T00:00:00-0400 or 1995-08-14T00:00:00+02:00)
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
            return formatter.parse(trimmed, Instant::from).toString();
        } catch (Exception ignored) {
        }

        // 3. Various standard datetime patterns
        List<DateTimeFormatter> formatters = List.of(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss").withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss").withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("dd-MMM-yyyy HH:mm:ss", Locale.ENGLISH).withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("dd-MMM-yyyy", Locale.ENGLISH).withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss").withZone(ZoneOffset.UTC),
                DateTimeFormatter.ofPattern("yyyy.MM.dd").withZone(ZoneOffset.UTC)
        );

        for (DateTimeFormatter fmt : formatters) {
            try {
                return fmt.parse(trimmed, Instant::from).toString();
            } catch (Exception ignored) {
            }
        }

        // 4. Try LocalDate fallback
        try {
            LocalDate ld = LocalDate.parse(trimmed);
            return ld.atStartOfDay(ZoneOffset.UTC).toInstant().toString();
        } catch (Exception ignored) {
        }

        return trimmed;
    }

    private RdapHttpResponse readHttpResponse(InputStream in) throws IOException {
        ByteArrayOutputStream headerBuffer = new ByteArrayOutputStream();
        int prev = -1;
        int curr;
        int headerBytes = 0;

        List<String> headerLines = new ArrayList<>();
        ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream();

        while ((curr = in.read()) != -1) {
            headerBytes++;
            if (headerBytes > 64 * 1024) {
                throw new IOException("HTTP response headers exceeded 64 KB");
            }
            if (curr == '\n' && prev == '\r') {
                byte[] bytes = lineBuffer.toByteArray();
                String line = new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.UTF_8);
                lineBuffer.reset();
                if (line.isEmpty()) {
                    break;
                }
                headerLines.add(line);
            } else {
                lineBuffer.write(curr);
            }
            prev = curr;
        }

        if (headerLines.isEmpty()) {
            throw new IOException("Empty HTTP response from RDAP endpoint");
        }

        String statusLine = headerLines.get(0);
        int statusCode = 500;
        String[] statusParts = statusLine.split(" ", 3);
        if (statusParts.length >= 2) {
            try {
                statusCode = Integer.parseInt(statusParts[1]);
            } catch (NumberFormatException ignored) {
            }
        }

        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < headerLines.size(); i++) {
            String h = headerLines.get(i);
            int colon = h.indexOf(':');
            if (colon > 0) {
                String name = h.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String val = h.substring(colon + 1).trim();
                headers.put(name, val);
            }
        }

        if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308
                || statusCode == 204 || statusCode == 304
                || "0".equals(headers.get("content-length"))) {
            return new RdapHttpResponse(statusCode, headers, "");
        }

        // Read body using PayloadLimitGuard
        String body = "";
        try (InputStream boundedStream = PayloadLimitGuard.wrap(in, PAYLOAD_CAP_BYTES, PAYLOAD_CAP_BYTES, false)) {
            if (headers.getOrDefault("transfer-encoding", "").toLowerCase(Locale.ROOT).contains("chunked")) {
                body = readChunkedBody(boundedStream);
            } else {
                body = new String(boundedStream.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        return new RdapHttpResponse(statusCode, headers, body);
    }

    private String readChunkedBody(InputStream in) throws IOException {
        ByteArrayOutputStream bodyOut = new ByteArrayOutputStream();
        while (true) {
            String line = readLine(in);
            if (line == null) {
                throw new IOException("Unexpected EOF while reading chunk size");
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            int semicolon = line.indexOf(';');
            String chunkSizeHex = semicolon >= 0 ? line.substring(0, semicolon).trim() : line;
            int chunkSize;
            try {
                chunkSize = Integer.parseInt(chunkSizeHex, 16);
            } catch (NumberFormatException e) {
                throw new IOException("Invalid chunk size: " + chunkSizeHex);
            }
            if (chunkSize < 0) {
                throw new IOException("Negative chunk size: " + chunkSize);
            }
            if (chunkSize == 0) {
                // Read trailers until empty line
                while (true) {
                    String trailer = readLine(in);
                    if (trailer == null || trailer.isEmpty()) {
                        break;
                    }
                }
                break;
            }
            byte[] chunk = in.readNBytes(chunkSize);
            if (chunk.length < chunkSize) {
                throw new IOException("Premature EOF reading chunk data");
            }
            bodyOut.write(chunk);
            // Read trailing CRLF after chunk data
            int b1 = in.read();
            if (b1 == '\r') {
                in.read(); // consume \n if present
            }
        }
        return bodyOut.toString(StandardCharsets.UTF_8);
    }

    private String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream lineBuf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                break;
            } else if (b != '\r') {
                lineBuf.write(b);
            }
        }
        if (b == -1 && lineBuf.size() == 0) {
            return null;
        }
        return lineBuf.toString(StandardCharsets.US_ASCII);
    }

    private record RdapHttpResponse(int statusCode, Map<String, String> headers, String body) {
        public String getHeader(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }
}
