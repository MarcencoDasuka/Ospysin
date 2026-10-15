package com.ospysin.tools.recon;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.ospysin.policy.DnsResolver;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.PolicyViolationException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StandardWhoisQueryClientTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeAll
    static void setUpAll() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            wireMockPort = socket.getLocalPort();
        }
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(wireMockPort));
        wireMockServer.start();
        WireMock.configureFor("127.0.0.1", wireMockPort);
    }

    @AfterAll
    static void tearDownAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @Test
    @DisplayName("SSRF Referral Falsification: blocks referral server resolving to 127.0.0.1 or 169.254.169.254 with PolicyViolationException")
    void ssrfReferralFalsificationBlocksPrivateAndMetadataReferral() {
        IpRangeValidator realValidator = new IpRangeValidator();
        DnsResolver dnsResolver = host -> {
            if ("evil-internal.example.com".equalsIgnoreCase(host)) {
                return new InetAddress[]{InetAddress.getByName("127.0.0.1")};
            } else if ("evil-metadata.example.com".equalsIgnoreCase(host)) {
                return new InetAddress[]{InetAddress.getByName("169.254.169.254")};
            }
            return new InetAddress[]{InetAddress.getByName("93.184.216.34")};
        };

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                realValidator,
                OBJECT_MAPPER,
                "https://rdap.mocked.org/domain/",
                "whois.iana.org",
                43
        );

        // Mock socket connector returning referral to evil-internal.example.com
        client.setSocketConnector((address, port, timeoutMs) -> new MockStringSocket("ReferralServer: whois://evil-internal.example.com\r\n"));

        assertThatThrownBy(() -> client.query("example.com", 2))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("WHOIS/RDAP destination blocked by policy")
                .hasMessageContaining("evil-internal.example.com");

        // Now test referral to cloud metadata
        client.setSocketConnector((address, port, timeoutMs) -> new MockStringSocket("refer: evil-metadata.example.com\r\n"));

        assertThatThrownBy(() -> client.query("example.com", 2))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("WHOIS/RDAP destination blocked by policy")
                .hasMessageContaining("evil-metadata.example.com");
    }

    @Test
    @DisplayName("SSRF Guard: blocks RDAP host resolving to private IP or metadata with PolicyViolationException")
    void ssrfGuardBlocksPrivateRdapEndpoint() {
        IpRangeValidator realValidator = new IpRangeValidator();
        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("10.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                realValidator,
                OBJECT_MAPPER,
                "http://rdap.internal.local/domain/",
                "whois.iana.org",
                43
        );

        assertThatThrownBy(() -> client.query("example.com", 1))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("WHOIS/RDAP destination blocked by policy");
    }

    @Test
    @DisplayName("query parses WireMock RDAP JSON response and redacts registrant PII")
    void queryParsesWireMockRdapJson() throws Exception {
        String rdapJson = """
                {
                  "objectClassName": "domain",
                  "handle": "2336799_DOMAIN_COM-VRSN",
                  "ldhName": "EXAMPLE.COM",
                  "status": ["clientTransferProhibited", "active"],
                  "entities": [
                    {
                      "roles": ["registrar"],
                      "vcardArray": [
                        "vcard",
                        [
                          ["version", {}, "text", "4.0"],
                          ["fn", {}, "text", "WireMock Registrar LLC"]
                        ]
                      ]
                    },
                    {
                      "roles": ["registrant"],
                      "vcardArray": [
                        "vcard",
                        [
                          ["version", {}, "text", "4.0"],
                          ["fn", {}, "text", "Secret John"],
                          ["email", {}, "text", "john@example.com"],
                          ["tel", {}, "text", "+1.5559998888"],
                          ["street", {}, "text", "123 Private Blvd"]
                        ]
                      ]
                    }
                  ],
                  "events": [
                    {
                      "eventAction": "registration",
                      "eventDate": "1995-08-14T04:00:00Z"
                    },
                    {
                      "eventAction": "expiration",
                      "eventDate": "2027-08-13T04:00:00Z"
                    }
                  ],
                  "nameservers": [
                    { "ldhName": "a.iana-servers.net" },
                    { "ldhName": "b.iana-servers.net" }
                  ]
                }
                """;

        wireMockServer.stubFor(get(urlEqualTo("/rdap/domain/example.com"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/rdap+json")
                        .withBody(rdapJson)));

        // Test validator allowing wiremock test host
        IpRangeValidator testValidator = new IpRangeValidator() {
            @Override
            public Optional<String> validate(InetAddress address, SessionMode mode) {
                return Optional.empty(); // allow test socket
            }
        };

        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                testValidator,
                OBJECT_MAPPER,
                "http://127.0.0.1:" + wireMockPort + "/rdap/domain/",
                "whois.iana.org",
                43
        );

        WhoisRawResult result = client.query("example.com", 1);

        assertThat(result.sourceProtocol()).isEqualTo("RDAP");
        assertThat(result.registrar()).isEqualTo("WireMock Registrar LLC");
        assertThat(result.createdDate()).isEqualTo("1995-08-14T04:00:00Z");
        assertThat(result.expiresDate()).isEqualTo("2027-08-13T04:00:00Z");
        assertThat(result.nameServers()).containsExactly("a.iana-servers.net", "b.iana-servers.net");
        assertThat(result.statuses()).contains("clientTransferProhibited", "active");

        // PII redaction check
        assertThat(result.rawOutput()).doesNotContain("john@example.com");
        assertThat(result.rawOutput()).doesNotContain("+1.5559998888");
        assertThat(result.rawOutput()).contains("[REDACTED]");
    }

    @Test
    @DisplayName("query falls back to Port 43 WHOIS when RDAP returns 404, follows referrals, and redacts text PII")
    void queryFallsBackToPort43AndFollowsReferrals() throws Exception {
        wireMockServer.stubFor(get(urlEqualTo("/rdap/domain/fallback.com"))
                .willReturn(aResponse().withStatus(404)));

        IpRangeValidator testValidator = new IpRangeValidator() {
            @Override
            public Optional<String> validate(InetAddress address, SessionMode mode) {
                return Optional.empty();
            }
        };

        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                testValidator,
                OBJECT_MAPPER,
                "http://127.0.0.1:" + wireMockPort + "/rdap/domain/",
                "whois.root.test",
                43
        );

        List<String> serverResponses = List.of(
                "refer: whois.tld.test\r\n",
                "Registrar WHOIS Server: whois.registrar.test\r\n",
                """
                Domain Name: FALLBACK.COM
                Registrar: Test Registrar Corp
                Creation Date: 2010-05-20T10:00:00Z
                Registry Expiry Date: 2028-05-20T10:00:00Z
                Name Server: ns1.fallback.com
                Name Server: ns2.fallback.com
                Domain Status: clientTransferProhibited
                Domain Status: clientDeleteProhibited
                Registrant Phone: +1.5551234567
                Registrant Email: admin@fallback.com
                Registrant Street: 456 Elm Street
                """
        );

        MockRoutingSocketFactory socketFactory = new MockRoutingSocketFactory(serverResponses);
        client.setSocketConnector((address, port, timeoutMs) -> socketFactory.createSocket());

        WhoisRawResult result = client.query("fallback.com", 3);

        assertThat(result.sourceProtocol()).isEqualTo("WHOIS");
        assertThat(result.registrar()).isEqualTo("Test Registrar Corp");
        assertThat(result.createdDate()).isEqualTo("2010-05-20T10:00:00Z");
        assertThat(result.expiresDate()).isEqualTo("2028-05-20T10:00:00Z");
        assertThat(result.nameServers()).containsExactly("ns1.fallback.com", "ns2.fallback.com");
        assertThat(result.statuses()).contains("clientTransferProhibited", "clientDeleteProhibited");
        assertThat(result.referralChain()).contains("whois.root.test", "whois.tld.test", "whois.registrar.test");

        // PII redaction check
        assertThat(result.rawOutput()).doesNotContain("+1.5551234567");
        assertThat(result.rawOutput()).doesNotContain("admin@fallback.com");
        assertThat(result.rawOutput()).doesNotContain("456 Elm Street");
        assertThat(result.rawOutput()).contains("Registrant Phone: [REDACTED]");
        assertThat(result.rawOutput()).contains("Registrant Email: [REDACTED]");
    }

    @Test
    @DisplayName("query stops referral loop (cycle detection) safely")
    void queryStopsReferralLoopSafely() throws Exception {
        wireMockServer.stubFor(get(urlEqualTo("/rdap/domain/loop.com"))
                .willReturn(aResponse().withStatus(500)));

        IpRangeValidator testValidator = new IpRangeValidator() {
            @Override
            public Optional<String> validate(InetAddress address, SessionMode mode) {
                return Optional.empty();
            }
        };

        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                testValidator,
                OBJECT_MAPPER,
                "http://127.0.0.1:" + wireMockPort + "/rdap/domain/",
                "whois.loop-a.test",
                43
        );

        List<String> loopResponses = List.of(
                "refer: whois.loop-b.test\r\n",
                "refer: whois.loop-a.test\r\n"
        );

        MockRoutingSocketFactory loopFactory = new MockRoutingSocketFactory(loopResponses);
        client.setSocketConnector((address, port, timeoutMs) -> loopFactory.createSocket());

        WhoisRawResult result = client.query("loop.com", 3);

        assertThat(result.sourceProtocol()).isEqualTo("WHOIS");
        assertThat(result.referralChain()).containsExactly("whois.loop-a.test", "whois.loop-b.test");
    }

    @Test
    @DisplayName("P13-01: RDAP redirect to disallowed scheme throws PolicyViolationException")
    void rdapRedirectDisallowedSchemeThrowsPolicyViolation() {
        wireMockServer.stubFor(get(urlEqualTo("/rdap/domain/ftp-redirect.com"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "ftp://evil.com/rdap/domain/ftp-redirect.com")));

        IpRangeValidator testValidator = new IpRangeValidator() {
            @Override
            public Optional<String> validate(InetAddress address, SessionMode mode) {
                return Optional.empty();
            }
        };

        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                testValidator,
                OBJECT_MAPPER,
                "http://127.0.0.1:" + wireMockPort + "/rdap/domain/",
                "whois.iana.org",
                43
        );

        assertThatThrownBy(() -> client.query("ftp-redirect.com", 2))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("Prohibited RDAP URL scheme: ftp");
    }

    @Test
    @DisplayName("P13-01: RDAP redirect to disallowed port throws PolicyViolationException")
    void rdapRedirectDisallowedPortThrowsPolicyViolation() {
        wireMockServer.stubFor(get(urlEqualTo("/rdap/domain/port-redirect.com"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "http://127.0.0.1:9999/rdap/domain/port-redirect.com")));

        IpRangeValidator testValidator = new IpRangeValidator() {
            @Override
            public Optional<String> validate(InetAddress address, SessionMode mode) {
                return Optional.empty();
            }
        };

        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                testValidator,
                OBJECT_MAPPER,
                "http://127.0.0.1:" + wireMockPort + "/rdap/domain/",
                "whois.iana.org",
                43
        );

        assertThatThrownBy(() -> client.query("port-redirect.com", 2))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("Prohibited RDAP port: 9999");
    }

    @Test
    @DisplayName("P13-01: RDAP parses chunked transfer encoding successfully")
    void rdapParsesChunkedTransferEncoding() throws Exception {
        String chunkedRdap = """
                {
                  "objectClassName": "domain",
                  "ldhName": "CHUNKED.COM",
                  "status": ["active"],
                  "entities": [
                    {
                      "roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Chunked Registrar"]]]
                    }
                  ],
                  "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}
                  ],
                  "nameservers": [{"ldhName": "ns1.chunked.com"}]
                }
                """;

        wireMockServer.stubFor(get(urlEqualTo("/rdap/domain/chunked.com"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Transfer-Encoding", "chunked")
                        .withHeader("Content-Type", "application/rdap+json")
                        .withBody(chunkedRdap)));

        IpRangeValidator testValidator = new IpRangeValidator() {
            @Override
            public Optional<String> validate(InetAddress address, SessionMode mode) {
                return Optional.empty();
            }
        };

        DnsResolver dnsResolver = host -> new InetAddress[]{InetAddress.getByName("127.0.0.1")};

        StandardWhoisQueryClient client = new StandardWhoisQueryClient(
                dnsResolver,
                testValidator,
                OBJECT_MAPPER,
                "http://127.0.0.1:" + wireMockPort + "/rdap/domain/",
                "whois.iana.org",
                43
        );

        WhoisRawResult result = client.query("chunked.com", 1);
        assertThat(result).isNotNull();
        assertThat(result.sourceProtocol()).isEqualTo("RDAP");
        assertThat(result.registrar()).isEqualTo("Chunked Registrar");
        assertThat(result.createdDate()).isEqualTo("2020-01-01T00:00:00Z");
        assertThat(result.expiresDate()).isEqualTo("2030-01-01T00:00:00Z");
        assertThat(result.nameServers()).containsExactly("ns1.chunked.com");
    }

    private static class MockStringSocket extends Socket {
        private final byte[] responseBytes;

        public MockStringSocket(String response) {
            this.responseBytes = response.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(responseBytes);
        }

        @Override
        public OutputStream getOutputStream() {
            return new ByteArrayOutputStream();
        }

        @Override
        public void close() {
        }
    }

    private static class MockRoutingSocketFactory {
        private final Queue<String> responses;

        public MockRoutingSocketFactory(List<String> responses) {
            this.responses = new LinkedList<>(responses);
        }

        public Socket createSocket() {
            return new Socket() {
                private final ByteArrayOutputStream output = new ByteArrayOutputStream();

                @Override
                public OutputStream getOutputStream() {
                    return output;
                }

                @Override
                public InputStream getInputStream() {
                    String sent = output.toString(StandardCharsets.UTF_8);
                    if (sent.startsWith("GET ")) {
                        String notFound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        return new ByteArrayInputStream(notFound.getBytes(StandardCharsets.UTF_8));
                    }
                    String next = responses.poll();
                    String resp = next != null ? next : "";
                    return new ByteArrayInputStream(resp.getBytes(StandardCharsets.UTF_8));
                }

                @Override
                public void close() {
                }
            };
        }
    }
}
