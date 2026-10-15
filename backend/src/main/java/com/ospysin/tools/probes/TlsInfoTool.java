package com.ospysin.tools.probes;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.ObfuscatedIpParser;
import com.ospysin.policy.PolicyDecision;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Tool #3: Direct TLS/SSL handshake, cipher suite, and certificate chain inspection probe.
 */
@Component
public class TlsInfoTool implements OspysinTool {

    public static final String TOOL_ID = "tls_info";
    public static final int DEFAULT_CONNECT_TIMEOUT_MS = 5000;
    public static final int DEFAULT_READ_TIMEOUT_MS = 10000;

    private final PolicyEngine policyEngine;
    private final Clock clock;

    @Autowired
    public TlsInfoTool(PolicyEngine policyEngine, Clock clock) {
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        if (params == null) {
            return;
        }

        if (params.containsKey("port") && params.get("port") != null) {
            int port = parsePort(params.get("port"));
            if (!PolicyEngine.ALLOWED_PORTS.contains(port)) {
                throw new ValidationException(
                        "Validation error for " + TOOL_ID,
                        List.of(new InvalidParam("port", "port must be one of allowed ports: " + PolicyEngine.ALLOWED_PORTS))
                );
            }
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        String targetHost = extractHost(context.targetUrl());
        int port = 443;

        if (context.inputParams().containsKey("port") && context.inputParams().get("port") != null) {
            port = parsePort(context.inputParams().get("port"));
        } else {
            int urlPort = extractPortFromUrl(context.targetUrl());
            if (urlPort != -1) {
                port = urlPort;
            }
        }

        // Validate port against PolicyEngine.ALLOWED_PORTS
        if (!PolicyEngine.ALLOWED_PORTS.contains(port)) {
            throw new PolicyViolationException(
                    "Policy violation for TLS probe port " + port + ": disallowed port",
                    List.of(new InvalidParam("port", "port must be one of allowed ports: " + PolicyEngine.ALLOWED_PORTS))
            );
        }

        InetAddress pinnedIp;
        if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null) {
            // Reuse pre-flight validated IP without redundant DNS resolution (P10-03)
            pinnedIp = context.policyDecision().resolvedIp();
        } else {
            String formattedHost = targetHost;
            if (targetHost.contains(":") && !targetHost.startsWith("[")) {
                formattedHost = "[" + targetHost + "]";
            }
            String probeUrl = "https://" + formattedHost + ":" + port;
            PolicyDecision decision = policyEngine.evaluate(probeUrl, context.mode(), context.scopeAsset());
            if (!decision.allowed()) {
                throw new PolicyViolationException(
                        "Policy violation for TLS probe on " + probeUrl + ": " + decision.reason(),
                        List.of(new InvalidParam("port", decision.reason()))
                );
            }
            pinnedIp = decision.resolvedIp();
        }

        InspectionTrustManager trustManager = new InspectionTrustManager();
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());

        String protocol;
        String cipherSuite;
        X509Certificate peerCert;
        X509Certificate[] certChain;

        try (Socket rawSocket = new Socket()) {
            rawSocket.connect(new InetSocketAddress(pinnedIp, port), DEFAULT_CONNECT_TIMEOUT_MS);
            rawSocket.setSoTimeout(DEFAULT_READ_TIMEOUT_MS);

            try (SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(rawSocket, targetHost, port, true)) {
                SSLParameters sslParams = sslSocket.getSSLParameters();
                if (!isIpLiteral(targetHost)) {
                    sslParams.setServerNames(List.of(new SNIHostName(targetHost)));
                }
                sslSocket.setSSLParameters(sslParams);
                sslSocket.startHandshake();

                SSLSession session = sslSocket.getSession();
                protocol = session.getProtocol();
                cipherSuite = session.getCipherSuite();

                Certificate[] peerCerts = null;
                try {
                    peerCerts = session.getPeerCertificates();
                } catch (SSLPeerUnverifiedException ignored) {
                }

                if (peerCerts != null && peerCerts.length > 0 && peerCerts[0] instanceof X509Certificate x509) {
                    peerCert = x509;
                    certChain = Arrays.copyOf(peerCerts, peerCerts.length, X509Certificate[].class);
                } else if (trustManager.getServerChain() != null && trustManager.getServerChain().length > 0) {
                    peerCert = trustManager.getServerChain()[0];
                    certChain = trustManager.getServerChain();
                } else {
                    throw new IOException("TLS handshake completed but no peer certificate chain was presented by " + targetHost);
                }
            }
        }

        // Parse certificate fields
        String subject = peerCert.getSubjectX500Principal().getName();
        String issuer = peerCert.getIssuerX500Principal().getName();
        String serialNumber = peerCert.getSerialNumber().toString(16);
        String sigAlgName = peerCert.getSigAlgName();
        String notBefore = peerCert.getNotBefore().toInstant().toString();
        String notAfter = peerCert.getNotAfter().toInstant().toString();
        long daysUntilExpiry = ChronoUnit.DAYS.between(clock.instant(), peerCert.getNotAfter().toInstant());

        boolean selfSigned = peerCert.getSubjectX500Principal().equals(peerCert.getIssuerX500Principal());
        if (selfSigned) {
            try {
                peerCert.verify(peerCert.getPublicKey());
            } catch (Exception ignored) {
            }
        }

        List<String> sanEntries = extractSanEntries(peerCert);
        String commonName = extractCommonName(subject);
        boolean hostnameVerified = Rfc9525Verifier.verifyHostname(targetHost, sanEntries, commonName);
        boolean trustVerified = trustManager.isTrustVerified();

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("protocol", protocol);
        parsedData.put("cipherSuite", cipherSuite);
        parsedData.put("subject", subject);
        parsedData.put("issuer", issuer);
        parsedData.put("serialNumber", serialNumber);
        parsedData.put("sigAlgName", sigAlgName);
        parsedData.put("notBefore", notBefore);
        parsedData.put("notAfter", notAfter);
        parsedData.put("daysUntilExpiry", daysUntilExpiry);
        parsedData.put("selfSigned", selfSigned);
        parsedData.put("sanEntries", sanEntries);
        parsedData.put("hostnameVerified", hostnameVerified);
        parsedData.put("trustVerified", trustVerified);

        List<ObservationDraft> observations = extractObservations(
                protocol,
                cipherSuite,
                daysUntilExpiry,
                selfSigned,
                hostnameVerified,
                targetHost
        );

        String rawOutput = buildRawOutput(
                targetHost,
                port,
                pinnedIp.getHostAddress(),
                protocol,
                cipherSuite,
                peerCert,
                certChain,
                daysUntilExpiry,
                selfSigned,
                hostnameVerified,
                trustVerified
        );

        // Architectural invariant: score = null (no scoring in direct target probes)
        return new ToolExecutionOutcome(
                rawOutput,
                parsedData,
                null,
                false,
                observations
        );
    }

    List<ObservationDraft> extractObservations(String protocol, String cipherSuite, long daysUntilExpiry,
                                               boolean selfSigned, boolean hostnameVerified, String targetHost) {
        List<ObservationDraft> observations = new ArrayList<>();

        // 1. Deprecated protocol (SSLv3, TLSv1, TLSv1.1)
        if ("SSLv3".equalsIgnoreCase(protocol) || "TLSv1".equalsIgnoreCase(protocol) || "TLSv1.1".equalsIgnoreCase(protocol)) {
            observations.add(new ObservationDraft(
                    "TLS_PROTOCOL",
                    "Deprecated TLS/SSL protocol in use: " + protocol,
                    SeverityHeuristic.HIGH
            ));
        }

        // 2. Weak cipher suite (RC4, 3DES, DES, NULL, ANON, EXPORT)
        String upperCipher = cipherSuite.toUpperCase(Locale.ROOT);
        if (upperCipher.contains("RC4") || upperCipher.contains("3DES") || upperCipher.contains("DES")
                || upperCipher.contains("NULL") || upperCipher.contains("ANON") || upperCipher.contains("EXPORT")) {
            observations.add(new ObservationDraft(
                    "TLS_CIPHER",
                    "Weak cipher suite in use: " + cipherSuite,
                    SeverityHeuristic.HIGH
            ));
        }

        // 3 & 4. Expired or expiring soon certificate
        if (daysUntilExpiry < 0) {
            observations.add(new ObservationDraft(
                    "TLS_CERTIFICATE",
                    "Peer certificate expired " + Math.abs(daysUntilExpiry) + " days ago",
                    SeverityHeuristic.HIGH
            ));
        } else if (daysUntilExpiry <= 30) {
            observations.add(new ObservationDraft(
                    "TLS_CERTIFICATE",
                    "Peer certificate will expire in " + daysUntilExpiry + " days",
                    SeverityHeuristic.MEDIUM
            ));
        }

        // 5. Self-signed certificate
        if (selfSigned) {
            observations.add(new ObservationDraft(
                    "TLS_CERTIFICATE",
                    "Peer certificate is self-signed",
                    SeverityHeuristic.MEDIUM
            ));
        }

        // 6. Hostname mismatch
        if (!hostnameVerified) {
            observations.add(new ObservationDraft(
                    "TLS_CERTIFICATE",
                    "Certificate hostname mismatch: target host '" + targetHost + "' does not match certificate SANs",
                    SeverityHeuristic.HIGH
            ));
        }

        return observations;
    }

    private List<String> extractSanEntries(X509Certificate cert) {
        List<String> result = new ArrayList<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> sanItem : sans) {
                    if (sanItem.size() >= 2 && sanItem.get(1) != null) {
                        result.add(sanItem.get(1).toString());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return result;
    }

    private String extractCommonName(String subjectDn) {
        if (subjectDn == null) {
            return null;
        }
        for (String part : subjectDn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase(Locale.ROOT).startsWith("CN=")) {
                return trimmed.substring(3).trim();
            }
        }
        return null;
    }

    String buildRawOutput(String targetHost, int port, String ip, String protocol, String cipherSuite,
                          X509Certificate cert, X509Certificate[] chain, long daysUntilExpiry,
                          boolean selfSigned, boolean hostnameVerified, boolean trustVerified) {
        StringBuilder sb = new StringBuilder();
        sb.append("TLS Connection Summary:\n");
        sb.append("  Target Host:       ").append(targetHost).append("\n");
        sb.append("  Port:              ").append(port).append("\n");
        sb.append("  Connected IP:      ").append(ip).append("\n");
        sb.append("  Negotiated Proto:  ").append(protocol).append("\n");
        sb.append("  Cipher Suite:      ").append(cipherSuite).append("\n\n");

        sb.append("Peer Certificate:\n");
        sb.append("  Subject:           ").append(cert.getSubjectX500Principal().getName()).append("\n");
        sb.append("  Issuer:            ").append(cert.getIssuerX500Principal().getName()).append("\n");
        sb.append("  Serial Number:     ").append(cert.getSerialNumber().toString(16)).append("\n");
        sb.append("  Signature Alg:     ").append(cert.getSigAlgName()).append("\n");
        sb.append("  Valid From:        ").append(cert.getNotBefore().toInstant()).append("\n");
        sb.append("  Valid Until:       ").append(cert.getNotAfter().toInstant()).append(" (");
        if (daysUntilExpiry < 0) {
            sb.append("EXPIRED ").append(Math.abs(daysUntilExpiry)).append(" days ago)\n");
        } else {
            sb.append(daysUntilExpiry).append(" days remaining)\n");
        }
        sb.append("  Self-Signed:       ").append(selfSigned).append("\n");
        sb.append("  RFC 9525 Match:    ").append(hostnameVerified).append("\n");
        sb.append("  Trust Verified:    ").append(trustVerified).append("\n");

        List<String> sans = extractSanEntries(cert);
        if (!sans.isEmpty()) {
            sb.append("  Subject Alt Names: ").append(String.join(", ", sans)).append("\n");
        }

        if (chain != null && chain.length > 1) {
            sb.append("\nCertificate Chain (").append(chain.length).append(" certificates):\n");
            for (int i = 0; i < chain.length; i++) {
                sb.append("  [").append(i).append("] ").append(chain[i].getSubjectX500Principal().getName()).append("\n");
            }
        }

        return sb.toString();
    }

    private String extractHost(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return "";
        }
        String trimmed = targetUrl.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                URI uri = URI.create(trimmed);
                String host = uri.getHost();
                if (host != null) {
                    if (host.startsWith("[") && host.endsWith("]")) {
                        host = host.substring(1, host.length() - 1);
                    }
                    return host;
                }
            } catch (Exception ignored) {
            }
        }
        int slash = trimmed.indexOf('/');
        if (slash > 0) {
            trimmed = trimmed.substring(0, slash);
        }
        int lastBracket = trimmed.lastIndexOf(']');
        if (lastBracket >= 0) {
            int colonAfterBracket = trimmed.indexOf(':', lastBracket);
            if (colonAfterBracket > 0) {
                trimmed = trimmed.substring(0, colonAfterBracket);
            }
        } else {
            int firstColon = trimmed.indexOf(':');
            int lastColon = trimmed.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon) {
                trimmed = trimmed.substring(0, firstColon);
            }
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
        }
        return trimmed;
    }

    private int extractPortFromUrl(String targetUrl) {
        if (targetUrl == null || targetUrl.isBlank()) {
            return -1;
        }
        try {
            if (targetUrl.contains("://")) {
                URI uri = URI.create(targetUrl.trim());
                return uri.getPort();
            }
        } catch (Exception ignored) {
        }
        return -1;
    }

    private boolean isIpLiteral(String host) {
        return ObfuscatedIpParser.parse(host) != null;
    }

    private int parsePort(Object val) {
        if (val == null) {
            return -1;
        }
        if (val instanceof Integer i) {
            return (i >= 1 && i <= 65535) ? i : -1;
        }
        if (val instanceof Short s) {
            int i = s.intValue();
            return (i >= 1 && i <= 65535) ? i : -1;
        }
        if (val instanceof Byte b) {
            int i = b.intValue();
            return (i >= 1 && i <= 65535) ? i : -1;
        }
        if (val instanceof Long l) {
            if (l < 1 || l > 65535) {
                return -1;
            }
            return l.intValue();
        }
        if (val instanceof String s) {
            try {
                long parsed = Long.parseLong(s.trim());
                if (parsed < 1 || parsed > 65535) {
                    return -1;
                }
                return (int) parsed;
            } catch (NumberFormatException ignored) {
                return -1;
            }
        }
        return -1;
    }
}
