package com.ospysin.tools.recon;

import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WhoisLookupToolTest {

    private WhoisLookupTool tool;
    private MockWhoisQueryClient mockClient;
    private Clock clock;
    private ScopeAsset scopeAsset;

    // Fixed test instant: 2026-10-15T00:00:00Z
    private static final Instant NOW = Instant.parse("2026-10-15T00:00:00Z");

    @BeforeEach
    void setUp() {
        clock = Clock.fixed(NOW, ZoneOffset.UTC);
        mockClient = new MockWhoisQueryClient();
        tool = new WhoisLookupTool(mockClient, clock);
        scopeAsset = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("example.com")
                .isWildcard(false)
                .build();
    }

    private ToolExecutionContext createContext(String targetUrl, Map<String, Object> inputParams) {
        return new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                targetUrl,
                SessionMode.PUBLIC,
                scopeAsset,
                inputParams,
                null
        );
    }

    @Test
    @DisplayName("validateParams accepts referralDepth between 0 and 3 or null/empty params")
    void validateParamsAcceptsValidDepth() {
        tool.validateParams(null);
        tool.validateParams(Map.of());
        tool.validateParams(Map.of("referralDepth", 0));
        tool.validateParams(Map.of("referralDepth", 1));
        tool.validateParams(Map.of("referralDepth", 2));
        tool.validateParams(Map.of("referralDepth", 3));
        tool.validateParams(Map.of("referralDepth", "2")); // numeric string
    }

    @Test
    @DisplayName("validateParams rejects negative referralDepth or greater than 3 with ValidationException")
    void validateParamsRejectsInvalidDepth() {
        assertThatThrownBy(() -> tool.validateParams(Map.of("referralDepth", -1)))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams().get(0).name()).isEqualTo("referralDepth");
                    assertThat(ve.getInvalidParams().get(0).reason()).contains("between 0 and 3");
                });

        assertThatThrownBy(() -> tool.validateParams(Map.of("referralDepth", 4)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("referralDepth", "not-a-number")))
                .isInstanceOf(ValidationException.class);

        Map<String, Object> nullParams = new HashMap<>();
        nullParams.put("referralDepth", null);
        assertThatThrownBy(() -> tool.validateParams(nullParams))
                .isInstanceOf(ValidationException.class);

        // P13-04: floating-point and overflow values
        assertThatThrownBy(() -> tool.validateParams(Map.of("referralDepth", 1.5)))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("referralDepth", 4294967297L)))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("execute extracts parsedData correctly from client result and calculates daysUntilExpiry")
    void executeExtractsParsedDataAndDaysUntilExpiry() throws Exception {
        // Expiration in 100 days: 2027-01-23T00:00:00Z
        String created = "1995-08-14T04:00:00Z";
        String expires = "2027-01-23T00:00:00Z";
        WhoisRawResult rawResult = new WhoisRawResult(
                "Domain Name: example.com\r\nRegistrar: Example Registrar LLC",
                "Example Registrar LLC",
                created,
                expires,
                List.of("ns1.example.com", "ns2.example.com"),
                List.of("clientTransferProhibited", "clientUpdateProhibited"),
                "RDAP",
                List.of("https://rdap.org/domain/example.com")
        );
        mockClient.setResult("example.com", rawResult);

        ToolExecutionContext context = createContext("https://example.com/", Map.of("referralDepth", 1));
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.score()).isNull();
        assertThat(outcome.parsedData().get("domain")).isEqualTo("example.com");
        assertThat(outcome.parsedData().get("registrar")).isEqualTo("Example Registrar LLC");
        assertThat(outcome.parsedData().get("createdDate")).isEqualTo(created);
        assertThat(outcome.parsedData().get("expiresDate")).isEqualTo(expires);
        assertThat(outcome.parsedData().get("daysUntilExpiry")).isEqualTo(100L);
        assertThat(outcome.parsedData().get("sourceProtocol")).isEqualTo("RDAP");
        assertThat(outcome.parsedData().get("statuses")).asList().contains("clientTransferProhibited");
        assertThat(outcome.observations()).isEmpty(); // No lifecycle warnings, lock present
    }

    @Test
    @DisplayName("execute flags expired domain with HIGH observation")
    void executeFlagsExpiredDomain() throws Exception {
        // Expired 10 days ago relative to 2026-10-15: 2026-10-05T00:00:00Z
        String expired = "2026-10-05T00:00:00Z";
        WhoisRawResult rawResult = new WhoisRawResult(
                "Domain Name: expired.com",
                "Some Registrar",
                "2020-01-01T00:00:00Z",
                expired,
                List.of("ns1.expired.com"),
                List.of("clientTransferProhibited"),
                "WHOIS",
                List.of("whois.iana.org")
        );
        mockClient.setResult("expired.com", rawResult);

        ToolExecutionContext context = createContext("http://expired.com", Map.of());
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.parsedData().get("daysUntilExpiry")).isEqualTo(-10L);
        assertThat(outcome.observations()).hasSize(1);

        ObservationDraft obs = outcome.observations().get(0);
        assertThat(obs.category()).isEqualTo("WHOIS_LIFECYCLE");
        assertThat(obs.severityHeuristic()).isEqualTo(SeverityHeuristic.HIGH);
        assertThat(obs.description()).isEqualTo("Domain registration expired 10 days ago");
    }

    @Test
    @DisplayName("execute flags domain expiring in <= 30 days with MEDIUM observation")
    void executeFlagsExpiringSoonDomain() throws Exception {
        // Expiring in 20 days: 2026-11-04T00:00:00Z
        String expiring = "2026-11-04T00:00:00Z";
        WhoisRawResult rawResult = new WhoisRawResult(
                "Domain Name: expiring-soon.com",
                "Fast Registrar",
                "2021-01-01T00:00:00Z",
                expiring,
                List.of("ns1.expiring-soon.com"),
                List.of("clientTransferProhibited"),
                "WHOIS",
                List.of("whois.iana.org")
        );
        mockClient.setResult("expiring-soon.com", rawResult);

        ToolExecutionContext context = createContext("https://expiring-soon.com", Map.of());
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.parsedData().get("daysUntilExpiry")).isEqualTo(20L);
        assertThat(outcome.observations()).hasSize(1);

        ObservationDraft obs = outcome.observations().get(0);
        assertThat(obs.category()).isEqualTo("WHOIS_LIFECYCLE");
        assertThat(obs.severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
        assertThat(obs.description()).isEqualTo("Domain registration expires in 20 days");
    }

    @Test
    @DisplayName("execute flags missing clientTransferProhibited lock with LOW observation")
    void executeFlagsMissingTransferLock() throws Exception {
        String expires = "2028-01-01T00:00:00Z";
        WhoisRawResult rawResult = new WhoisRawResult(
                "Domain Name: unlocked.com",
                "Unlocked Registrar",
                "2020-01-01T00:00:00Z",
                expires,
                List.of("ns1.unlocked.com"),
                List.of("active", "ok"), // No clientTransferProhibited!
                "WHOIS",
                List.of("whois.iana.org")
        );
        mockClient.setResult("unlocked.com", rawResult);

        ToolExecutionContext context = createContext("https://unlocked.com", Map.of());
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.observations()).hasSize(1);
        ObservationDraft obs = outcome.observations().get(0);
        assertThat(obs.category()).isEqualTo("WHOIS_SECURITY");
        assertThat(obs.severityHeuristic()).isEqualTo(SeverityHeuristic.LOW);
        assertThat(obs.description()).isEqualTo("Domain does not have clientTransferProhibited lock enabled");
    }

    @Test
    @DisplayName("execute handles localhost and private IP targets gracefully without crashing")
    void executeHandlesLocalhostAndPrivateIpGracefully() throws Exception {
        ToolExecutionContext lhContext = createContext("http://localhost:8080/dashboard", Map.of());
        ToolExecutionOutcome lhOutcome = tool.execute(lhContext);

        assertThat(lhOutcome.hasErrors()).isFalse();
        assertThat(lhOutcome.parsedData().get("registered")).isEqualTo(false);
        assertThat(lhOutcome.parsedData().get("registrar")).isEqualTo("N/A");
        assertThat(lhOutcome.observations()).isEmpty();
        assertThat(lhOutcome.rawOutput()).contains("local or private address");

        ToolExecutionContext ipContext = createContext("http://192.168.1.50/admin", Map.of());
        ToolExecutionOutcome ipOutcome = tool.execute(ipContext);

        assertThat(ipOutcome.hasErrors()).isFalse();
        assertThat(ipOutcome.parsedData().get("registered")).isEqualTo(false);
        assertThat(ipOutcome.observations()).isEmpty();

        ToolExecutionContext loopbackContext = createContext("http://127.0.0.1:3000", Map.of());
        ToolExecutionOutcome loopbackOutcome = tool.execute(loopbackContext);

        assertThat(loopbackOutcome.hasErrors()).isFalse();
        assertThat(loopbackOutcome.parsedData().get("registered")).isEqualTo(false);

        // P13-02: IPv6 ULA target and trailing-dot target
        ToolExecutionContext ulaContext = createContext("http://[fd00::1]:8080/path", Map.of());
        ToolExecutionOutcome ulaOutcome = tool.execute(ulaContext);
        assertThat(ulaOutcome.hasErrors()).isFalse();
        assertThat(ulaOutcome.parsedData().get("registered")).isEqualTo(false);

        ToolExecutionContext dotContext = createContext("http://localhost.:8080", Map.of());
        ToolExecutionOutcome dotOutcome = tool.execute(dotContext);
        assertThat(dotOutcome.hasErrors()).isFalse();
        assertThat(dotOutcome.parsedData().get("registered")).isEqualTo(false);
    }

    @Test
    @DisplayName("execute enforces 32 KB cap on raw output")
    void executeEnforces32KbCap() throws Exception {
        String largeRaw = "x".repeat(50 * 1024);
        WhoisRawResult largeResult = new WhoisRawResult(
                largeRaw,
                "Big Registrar",
                null,
                null,
                List.of(),
                List.of(),
                "WHOIS",
                List.of()
        );
        mockClient.setResult("big.com", largeResult);

        ToolExecutionContext context = createContext("https://big.com", Map.of());
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.rawOutput().length()).isLessThanOrEqualTo(32 * 1024);
    }

    @Test
    @DisplayName("P13-03: execute truncates multi-byte UTF-8 string to <= 32 KB without splitting code points")
    void executeTruncatesMultiByteUtf8To32Kb() throws Exception {
        String multiByteRaw = "€".repeat(15_000);
        WhoisRawResult rawResult = new WhoisRawResult(
                multiByteRaw,
                "Euro Registrar",
                null,
                null,
                List.of(),
                List.of(),
                "WHOIS",
                List.of()
        );
        mockClient.setResult("euro.com", rawResult);

        ToolExecutionContext context = createContext("https://euro.com", Map.of());
        ToolExecutionOutcome outcome = tool.execute(context);

        byte[] outputBytes = outcome.rawOutput().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(outputBytes.length).isLessThanOrEqualTo(32 * 1024);
        assertThat(outputBytes.length % 3).isEqualTo(0);
    }

    private static class MockWhoisQueryClient implements WhoisQueryClient {
        private final Map<String, WhoisRawResult> results = new HashMap<>();

        public void setResult(String host, WhoisRawResult result) {
            results.put(host.toLowerCase(Locale.ROOT), result);
        }

        @Override
        public WhoisRawResult query(String domainOrIp, int maxReferralDepth) {
            WhoisRawResult res = results.get(domainOrIp.toLowerCase(Locale.ROOT));
            if (res != null) {
                return res;
            }
            return new WhoisRawResult(
                    "Domain: " + domainOrIp,
                    "Unknown",
                    null,
                    null,
                    List.of(),
                    List.of(),
                    "WHOIS",
                    List.of()
            );
        }
    }
}
