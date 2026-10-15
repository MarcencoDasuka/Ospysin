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

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DnsLookupToolTest {

    private DnsLookupTool tool;
    private MockDnsLookupClient mockClient;
    private ScopeAsset scopeAsset;

    @BeforeEach
    void setUp() {
        mockClient = new MockDnsLookupClient();
        tool = new DnsLookupTool(mockClient);
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
    @DisplayName("validateParams accepts allowed record types and null or empty params")
    void validateParamsAcceptsValidTypes() {
        tool.validateParams(null);
        tool.validateParams(Map.of());
        tool.validateParams(Map.of("recordTypes", List.of("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "PTR", "CNAME")));
        tool.validateParams(Map.of("recordTypes", List.of("a", "mx", "txt"))); // case-insensitive
    }

    @Test
    @DisplayName("validateParams rejects invalid recordTypes with ValidationException")
    void validateParamsRejectsInvalidTypes() {
        assertThatThrownBy(() -> tool.validateParams(Map.of("recordTypes", "not-a-list")))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams()).anyMatch(p -> p.name().equals("recordTypes"));
                });

        assertThatThrownBy(() -> tool.validateParams(Map.of("recordTypes", List.of())))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("recordTypes", List.of("INVALID_TYPE"))))
                .isInstanceOf(ValidationException.class)
                .satisfies(ex -> {
                    ValidationException ve = (ValidationException) ex;
                    assertThat(ve.getInvalidParams().get(0).reason()).contains("Disallowed record type");
                });

        assertThatThrownBy(() -> tool.validateParams(Map.of("recordTypes", Collections.singletonList(null))))
                .isInstanceOf(ValidationException.class);

        assertThatThrownBy(() -> tool.validateParams(Map.of("recordTypes", List.of("   "))))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("execute queries default record types and produces structured parsedData")
    void executeQueriesDefaultRecordTypes() throws Exception {
        mockClient.addRecords("example.com", "A", List.of("93.184.216.34"));
        mockClient.addRecords("example.com", "AAAA", List.of("2606:2800:220:1:248:1893:25c8:1946"));
        mockClient.addRecords("example.com", "MX", List.of("10 mail.example.com."));
        mockClient.addRecords("example.com", "TXT", List.of("v=spf1 -all"));
        mockClient.addRecords("_dmarc.example.com", "TXT", List.of("v=DMARC1; p=reject"));
        mockClient.addRecords("example.com", "CAA", List.of("0 issue \"letsencrypt.org\""));
        mockClient.addRecords("example.com", "NS", List.of("ns1.example.com.", "ns2.example.com."));
        mockClient.addRecords("example.com", "CNAME", List.of());

        ToolExecutionContext context = createContext("https://example.com/", Map.of());
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.score()).isNull();
        assertThat(outcome.parsedData().get("domain")).isEqualTo("example.com");
        assertThat(outcome.parsedData().get("spfPresent")).isEqualTo(true);
        assertThat(outcome.parsedData().get("dmarcPresent")).isEqualTo(true);
        assertThat(outcome.parsedData().get("caaPresent")).isEqualTo(true);

        @SuppressWarnings("unchecked")
        Map<String, List<String>> records = (Map<String, List<String>>) outcome.parsedData().get("records");
        assertThat(records).isNotNull();
        assertThat(records.get("A")).containsExactly("93.184.216.34");
        assertThat(records.get("MX")).containsExactly("10 mail.example.com.");
        assertThat(records.get("TXT")).containsExactly("v=spf1 -all");

        // SPF and DMARC are secure and CAA is present -> no security observations
        assertThat(outcome.observations()).isEmpty();
        assertThat(outcome.rawOutput()).contains("; DNS Record Enumeration for example.com");
        assertThat(outcome.rawOutput()).contains("93.184.216.34");
    }

    @Test
    @DisplayName("execute flags missing SPF and missing DMARC as LOW observations")
    void executeFlagsMissingSpfAndDmarc() throws Exception {
        mockClient.addRecords("vulnerable.com", "A", List.of("1.2.3.4"));
        mockClient.addRecords("vulnerable.com", "TXT", List.of("some-other-txt=value"));
        // No SPF, no DMARC, no CAA

        ToolExecutionContext context = createContext("http://vulnerable.com", Map.of("recordTypes", List.of("A", "TXT", "CAA")));
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.parsedData().get("spfPresent")).isEqualTo(false);
        assertThat(outcome.parsedData().get("dmarcPresent")).isEqualTo(false);
        assertThat(outcome.parsedData().get("caaPresent")).isEqualTo(false);

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(3);

        ObservationDraft spfObs = observations.stream()
                .filter(o -> o.description().contains("Missing SPF"))
                .findFirst().orElseThrow();
        assertThat(spfObs.severityHeuristic()).isEqualTo(SeverityHeuristic.LOW);
        assertThat(spfObs.category()).isEqualTo("DNS_SECURITY");

        ObservationDraft dmarcObs = observations.stream()
                .filter(o -> o.description().contains("Missing DMARC"))
                .findFirst().orElseThrow();
        assertThat(dmarcObs.severityHeuristic()).isEqualTo(SeverityHeuristic.LOW);

        ObservationDraft caaObs = observations.stream()
                .filter(o -> o.description().contains("CAA"))
                .findFirst().orElseThrow();
        assertThat(caaObs.severityHeuristic()).isEqualTo(SeverityHeuristic.INFO);
    }

    @Test
    @DisplayName("execute flags overly permissive SPF (+all or ?all) as MEDIUM observation")
    void executeFlagsPermissiveSpf() throws Exception {
        mockClient.addRecords("spoofable.com", "TXT", List.of("v=spf1 include:_spf.google.com +all"));
        mockClient.addRecords("_dmarc.spoofable.com", "TXT", List.of("v=DMARC1; p=none"));

        ToolExecutionContext context = createContext("https://spoofable.com", Map.of("recordTypes", List.of("TXT")));
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.parsedData().get("spfPresent")).isEqualTo(true);
        assertThat(outcome.parsedData().get("dmarcPresent")).isEqualTo(true);

        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).hasSize(1);
        assertThat(observations.get(0).category()).isEqualTo("DNS_SECURITY");
        assertThat(observations.get(0).severityHeuristic()).isEqualTo(SeverityHeuristic.MEDIUM);
        assertThat(observations.get(0).description()).contains("Permissive SPF policy");
        assertThat(observations.get(0).description()).contains("+all");
    }

    @Test
    @DisplayName("execute handles IP literal and localhost targets gracefully without crashing or emitting domain observations")
    void executeHandlesIpLiteralsAndLocalhostGracefully() throws Exception {
        mockClient.addRecords("127.0.0.1", "PTR", List.of("localhost."));

        ToolExecutionContext ipContext = createContext("http://127.0.0.1:8080/app", Map.of("recordTypes", List.of("A", "PTR", "TXT")));
        ToolExecutionOutcome ipOutcome = tool.execute(ipContext);

        assertThat(ipOutcome.hasErrors()).isFalse();
        assertThat(ipOutcome.parsedData().get("domain")).isEqualTo("127.0.0.1");
        assertThat(ipOutcome.observations()).isEmpty();

        ToolExecutionContext localhostContext = createContext("http://localhost:3000/", Map.of());
        ToolExecutionOutcome lhOutcome = tool.execute(localhostContext);

        assertThat(lhOutcome.hasErrors()).isFalse();
        assertThat(lhOutcome.parsedData().get("domain")).isEqualTo("localhost");
        assertThat(lhOutcome.observations()).isEmpty();
    }

    @Test
    @DisplayName("execute enforces 32 KB cap on raw output")
    void executeEnforces32KbCap() throws Exception {
        List<String> largeList = new ArrayList<>();
        for (int i = 0; i < 2000; i++) {
            largeList.add("txt-record-entry-number-" + i + "-with-some-padding-data-to-expand-bytes");
        }
        mockClient.addRecords("huge.example.com", "TXT", largeList);

        ToolExecutionContext context = createContext("https://huge.example.com/", Map.of("recordTypes", List.of("TXT")));
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.rawOutput().length()).isLessThanOrEqualTo(32 * 1024);
    }

    @Test
    @DisplayName("P13-05: anchored SPF and DMARC regex matching avoids false positives on commentary records")
    void executeAvoidsFalsePositiveOnCommentaryTxtRecords() throws Exception {
        mockClient.addRecords("commentary.com", "A", List.of("1.1.1.1"));
        mockClient.addRecords("commentary.com", "TXT", List.of("doc note: see v=spf1 specification for guidance"));
        mockClient.addRecords("_dmarc.commentary.com", "TXT", List.of("policy note: refer to v=dmarc1 documentation"));

        ToolExecutionContext context = createContext("https://commentary.com/", Map.of("recordTypes", List.of("TXT")));
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.parsedData().get("spfPresent")).isEqualTo(false);
        assertThat(outcome.parsedData().get("dmarcPresent")).isEqualTo(false);
        assertThat(outcome.observations()).anyMatch(o -> o.description().contains("Missing SPF"));
        assertThat(outcome.observations()).anyMatch(o -> o.description().contains("Missing DMARC"));
    }

    @Test
    @DisplayName("P13-02: trailing dot target URL normalizes to FQDN without trailing dot")
    void executeNormalizesTrailingDotInTargetUrl() throws Exception {
        mockClient.addRecords("example.com", "A", List.of("93.184.216.34"));
        mockClient.addRecords("example.com", "TXT", List.of("v=spf1 -all"));
        mockClient.addRecords("_dmarc.example.com", "TXT", List.of("v=DMARC1; p=reject"));

        ToolExecutionContext context = createContext("https://example.com./", Map.of("recordTypes", List.of("A", "TXT")));
        ToolExecutionOutcome outcome = tool.execute(context);

        assertThat(outcome.parsedData().get("domain")).isEqualTo("example.com");
        assertThat(outcome.parsedData().get("spfPresent")).isEqualTo(true);
        assertThat(outcome.parsedData().get("dmarcPresent")).isEqualTo(true);
    }

    @Test
    @DisplayName("P13-03: execute truncates multi-byte UTF-8 string to <= 32 KB without splitting code points")
    void executeTruncatesMultiByteUtf8To32Kb() throws Exception {
        List<String> largeList = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            largeList.add("€€€€€€€€€€€€€€€€€€€€" + i);
        }
        mockClient.addRecords("multibyte.com", "TXT", largeList);

        ToolExecutionContext context = createContext("https://multibyte.com/", Map.of("recordTypes", List.of("TXT")));
        ToolExecutionOutcome outcome = tool.execute(context);

        byte[] outputBytes = outcome.rawOutput().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(outputBytes.length).isLessThanOrEqualTo(32 * 1024);
    }

    private static class MockDnsLookupClient implements DnsLookupClient {
        private final Map<String, Map<String, List<String>>> domainRecords = new HashMap<>();

        public void addRecords(String domain, String type, List<String> records) {
            domainRecords.computeIfAbsent(domain.toLowerCase(Locale.ROOT), k -> new HashMap<>())
                    .put(type.toUpperCase(Locale.ROOT), records);
        }

        @Override
        public List<String> queryRecords(String domain, String recordType) {
            Map<String, List<String>> types = domainRecords.get(domain.toLowerCase(Locale.ROOT));
            if (types == null) {
                return Collections.emptyList();
            }
            List<String> recs = types.get(recordType.toUpperCase(Locale.ROOT));
            return recs != null ? recs : Collections.emptyList();
        }
    }
}
