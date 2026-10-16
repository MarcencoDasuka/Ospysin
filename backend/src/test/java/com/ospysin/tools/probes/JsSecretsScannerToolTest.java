package com.ospysin.tools.probes;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.HostRateLimiter;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.policy.IpRangeValidator;
import com.ospysin.policy.PolicyEngine;
import com.ospysin.policy.io.AggregatePayloadBudget;
import com.ospysin.policy.io.PayloadLimitExceededException;
import com.ospysin.scope.AssetType;
import com.ospysin.scope.ScopeAsset;
import com.ospysin.sessions.SessionMode;
import com.ospysin.shared.error.PolicyViolationException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

class JsSecretsScannerToolTest {

    private static WireMockServer wireMockServer;
    private static int wireMockPort;
    private static PolicyEngine policyEngine;
    private static PinnedHttpClient pinnedHttpClient;
    private static ToolExecutionRepository toolExecutionRepo;
    private static ToolResultRepository toolResultRepo;
    private static HostRateLimiter hostRateLimiter;
    private static JsSecretsScannerTool tool;
    private static ScopeAsset localScopeAsset;

    @BeforeAll
    static void setUpAll() {
        wireMockPort = findFreeAllowedPort();
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(wireMockPort));
        wireMockServer.start();
        WireMock.configureFor("127.0.0.1", wireMockPort);

        Clock clock = Clock.fixed(Instant.parse("2026-10-15T00:00:00Z"), ZoneOffset.UTC);
        IpRangeValidator ipRangeValidator = new IpRangeValidator();
        policyEngine = new PolicyEngine(ipRangeValidator, host -> new InetAddress[]{InetAddress.getByName(host)}, clock);

        pinnedHttpClient = new PinnedHttpClient(policyEngine);
        toolExecutionRepo = Mockito.mock(ToolExecutionRepository.class);
        toolResultRepo = Mockito.mock(ToolResultRepository.class);
        hostRateLimiter = Mockito.mock(HostRateLimiter.class);

        tool = new JsSecretsScannerTool(pinnedHttpClient, policyEngine, toolExecutionRepo, toolResultRepo, hostRateLimiter);

        localScopeAsset = ScopeAsset.builder()
                .assetType(AssetType.IP)
                .value("127.0.0.1")
                .isWildcard(false)
                .build();
    }

    @AfterAll
    static void tearDownAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @BeforeEach
    void resetMocks() {
        wireMockServer.resetAll();
        Mockito.reset(toolExecutionRepo, toolResultRepo, hostRateLimiter);
    }

    @Test
    @DisplayName("validateParams rejects invalid jsUrls and out-of-range maxFiles")
    void validateParamsRejectsInvalidInput() {
        // jsUrls not a list
        assertThatThrownBy(() -> tool.validateParams(Map.of("jsUrls", "http://example.com/app.js")))
                .isInstanceOf(ValidationException.class);

        // jsUrls item with missing scheme
        assertThatThrownBy(() -> tool.validateParams(Map.of("jsUrls", List.of("example.com/app.js"))))
                .isInstanceOf(ValidationException.class);

        // jsUrls item with CRLF
        assertThatThrownBy(() -> tool.validateParams(Map.of("jsUrls", List.of("http://example.com/app.js\r\n"))))
                .isInstanceOf(ValidationException.class);

        // maxFiles out of range
        assertThatThrownBy(() -> tool.validateParams(Map.of("maxFiles", 0)))
                .isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> tool.validateParams(Map.of("maxFiles", 51)))
                .isInstanceOf(ValidationException.class);

        // Null jsUrls
        Map<String, Object> nullJsUrls = new HashMap<>();
        nullJsUrls.put("jsUrls", null);
        assertThatThrownBy(() -> tool.validateParams(nullJsUrls))
                .isInstanceOf(ValidationException.class);

        // Null maxFiles
        Map<String, Object> nullMaxFiles = new HashMap<>();
        nullMaxFiles.put("maxFiles", null);
        assertThatThrownBy(() -> tool.validateParams(nullMaxFiles))
                .isInstanceOf(ValidationException.class);

        // Valid params
        tool.validateParams(Map.of("jsUrls", List.of("http://example.com/bundle.js"), "maxFiles", 5));
        tool.validateParams(Collections.emptyMap());
    }

    @Test
    @DisplayName("Shannon entropy calculation validates expected thresholds")
    void validatesShannonEntropyCalculation() {
        assertThat(JsSecretsScannerTool.calculateShannonEntropy("")).isEqualTo(0.0);
        assertThat(JsSecretsScannerTool.calculateShannonEntropy("aaaaaaaaaaaaaaaa")).isEqualTo(0.0);
        // Random high-entropy token
        double highEntropy = JsSecretsScannerTool.calculateShannonEntropy("xK9!mQ2#pL8$vN4%jR7^tY1&");
        assertThat(highEntropy).isGreaterThan(3.5);
    }

    @Test
    @DisplayName("Masking logic replaces secret center with ***masked***")
    void validatesSecretMasking() {
        assertThat(JsSecretsScannerTool.maskSecret("AIzaSyD-1234567890abcdefghijklmnopqrst")).contains("***masked***");
        assertThat(JsSecretsScannerTool.maskSecret("-----BEGIN RSA PRIVATE KEY-----")).contains("***masked***");
        assertThat(JsSecretsScannerTool.maskSecret("short")).isEqualTo("***masked***");
    }

    @Test
    @DisplayName("Scans JS bundle for AWS, GCP, Stripe, GitHub, Private Key, JWT, and high-entropy secrets with 1-based lines")
    void scansAllSecretSignaturesAccurately() throws Exception {
        String jsContent = "console.log(\"Loading App Bundle...\");\n"
                + "const awsKey = \"" + "AKIA" + "1234567890ABCDEF\";\n"
                + "const googleApiKey = \"" + "AIzaSy" + "D-1234567890abcdefghijklmnopqrstu\";\n"
                + "const stripeLive = \"" + "sk_live_" + "abcdefghijklmnopqrstuvwxyz12345\";\n"
                + "const stripeTest = \"" + "sk_test_" + "abcdefghijklmnopqrstuvwxyz12345\";\n"
                + "const githubToken = \"" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz\";\n"
                + "const privateKeyHeader = \"-----BEGIN RSA PRIVATE KEY-----\";\n"
                + "const jwtToken = \"" + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "abcdefghijklmnopqrstuvwxyz1234567890\";\n"
                + "const clientSecret = \"xK9!mQ2#pL8$vN4%jR7^tY1&\";\n"
                + "const regularWord = \"placeholder_example_string_here\";\n";

        stubFor(get(urlEqualTo("/static/app.bundle.js"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/javascript")
                        .withBody(jsContent)));

        String jsUrl = "http://127.0.0.1:" + wireMockPort + "/static/app.bundle.js";
        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://127.0.0.1:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("jsUrls", List.of(jsUrl)),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.score()).isNull();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("filesScanned")).isEqualTo(1);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> findings = (List<Map<String, Object>>) data.get("findings");
        assertThat(findings).isNotEmpty();

        // 1. AWS Key at line 2
        assertThat(findings).anyMatch(f -> "AWS Access Key ID".equals(f.get("secretType"))
                && Integer.valueOf(2).equals(f.get("line"))
                && ((String) f.get("match")).contains("***masked***")
                && "HIGH".equals(f.get("severity")));

        // 2. Google Cloud Key at line 3
        assertThat(findings).anyMatch(f -> "Google Cloud API Key".equals(f.get("secretType"))
                && Integer.valueOf(3).equals(f.get("line"))
                && ((String) f.get("match")).contains("***masked***"));

        // 3. Stripe Live (CRITICAL) at line 4
        assertThat(findings).anyMatch(f -> "Stripe Secret Key".equals(f.get("secretType"))
                && Integer.valueOf(4).equals(f.get("line"))
                && "CRITICAL".equals(f.get("severity")));

        // 4. Stripe Test (HIGH) at line 5
        assertThat(findings).anyMatch(f -> "Stripe Secret Key".equals(f.get("secretType"))
                && Integer.valueOf(5).equals(f.get("line"))
                && "HIGH".equals(f.get("severity")));

        // 5. GitHub PAT at line 6
        assertThat(findings).anyMatch(f -> "GitHub Personal Access Token".equals(f.get("secretType"))
                && Integer.valueOf(6).equals(f.get("line")));

        // 6. Private Key at line 7
        assertThat(findings).anyMatch(f -> "Private Key".equals(f.get("secretType"))
                && Integer.valueOf(7).equals(f.get("line"))
                && "CRITICAL".equals(f.get("severity")));

        // 7. JWT at line 8
        assertThat(findings).anyMatch(f -> "JSON Web Token (JWT)".equals(f.get("secretType"))
                && Integer.valueOf(8).equals(f.get("line")));

        // 8. High-entropy secret at line 9
        assertThat(findings).anyMatch(f -> "Hardcoded High-Entropy Secret".equals(f.get("secretType"))
                && Integer.valueOf(9).equals(f.get("line")));

        // Excluded keyword should not be flagged
        assertThat(findings).noneMatch(f -> ((String) f.get("match")).contains("placeholder"));

        // Verify ObservationDrafts generated
        List<ObservationDraft> observations = outcome.observations();
        assertThat(observations).isNotEmpty();
        assertThat(observations).allMatch(o -> "JS_SECRET_LEAK".equals(o.category()));
        assertThat(observations).anyMatch(o -> o.description().contains("AWS Access Key ID")
                && o.severityHeuristic() == SeverityHeuristic.HIGH);

        Mockito.verify(hostRateLimiter, Mockito.atLeastOnce()).acquire(Mockito.anyString());
    }

    @Test
    @DisplayName("Auto-discovers scripts from completed extract_js_urls step with BOLA session isolation")
    void autoDiscoversFromPriorSessionStep() throws Exception {
        UUID sessionId = UUID.randomUUID();
        UUID otherSessionId = UUID.randomUUID();
        UUID extractExecId = UUID.randomUUID();

        String jsUrl = "http://127.0.0.1:" + wireMockPort + "/assets/discovered.js";
        stubFor(get(urlEqualTo("/assets/discovered.js"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody("const apiKey = \"AIzaSyD-9876543210zyxwvutsrqponmlkjihgfedcba\";")));

        // Seed mock execution in current session
        ToolExecution execution = ToolExecution.builder()
                .session(null)
                .toolId("extract_js_urls")
                .status(ExecutionStatus.COMPLETED)
                .inputParams(Map.of())
                .leaseEpoch(1)
                .attempts(1)
                .build();
        // Reflection set id
        var idField = ToolExecution.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(execution, extractExecId);

        when(toolExecutionRepo.findBySessionIdOrderByCreatedAtAsc(sessionId))
                .thenReturn(List.of(execution));

        ToolResult toolResult = ToolResult.builder()
                .execution(execution)
                .rawOutput("dummy")
                .parsedData(Map.of("scripts", List.of(
                        Map.of("src", jsUrl, "isInternal", true)
                )))
                .hasErrors(false)
                .build();

        when(toolResultRepo.findByExecutionId(extractExecId))
                .thenReturn(Optional.of(toolResult));

        // BOLA test: other session queries return empty
        when(toolExecutionRepo.findBySessionIdOrderByCreatedAtAsc(otherSessionId))
                .thenReturn(Collections.emptyList());

        ToolExecutionContext context = new ToolExecutionContext(
                sessionId,
                UUID.randomUUID(),
                "http://127.0.0.1:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of(),
                null
        );

        ToolExecutionOutcome outcome = tool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("filesScanned")).isEqualTo(1);
        assertThat(data.get("totalSecretsFound")).isEqualTo(1);
    }

    @Test
    @DisplayName("PolicyEngine SSRF rejection when explicit jsUrls contains out-of-scope host")
    void rejectsOutOfScopeJsUrls() {
        ScopeAsset restrictedScope = ScopeAsset.builder()
                .assetType(AssetType.FQDN)
                .value("authorized.example.com")
                .isWildcard(false)
                .build();

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://authorized.example.com",
                SessionMode.PUBLIC,
                restrictedScope,
                Map.of("jsUrls", List.of("http://evil-attacker.com/malicious.js")),
                null
        );

        assertThatThrownBy(() -> tool.execute(context))
                .isInstanceOf(PolicyViolationException.class)
                .hasMessageContaining("outside authorized scope");
    }

    @Test
    @DisplayName("Tier 3 AggregatePayloadBudget stops further downloads cleanly when aggregate budget exceeded")
    void stopsDownloadWhenAggregateBudgetExceeded() throws Exception {
        PinnedHttpClient exceedingClient = new PinnedHttpClient(policyEngine) {
            @Override
            public PinnedProbeResult executeWithRedirects(
                    URI initialUri,
                    InetAddress initialIp,
                    boolean followRedirects,
                    SessionMode mode,
                    ScopeAsset scopeAsset,
                    long maxWireBytes,
                    long maxDecompressedBytes,
                    int readTimeoutMs,
                    AggregatePayloadBudget aggregateBudget
            ) throws IOException, PolicyViolationException {
                if (aggregateBudget != null) {
                    // Exceed 5 MB aggregate budget
                    aggregateBudget.track(6 * 1024 * 1024L);
                }
                return super.executeWithRedirects(initialUri, initialIp, followRedirects, mode, scopeAsset, maxWireBytes, maxDecompressedBytes, readTimeoutMs, aggregateBudget);
            }
        };

        JsSecretsScannerTool budgetTool = new JsSecretsScannerTool(exceedingClient, policyEngine, toolExecutionRepo, toolResultRepo, hostRateLimiter);

        String jsUrl1 = "http://127.0.0.1:" + wireMockPort + "/large1.js";
        String jsUrl2 = "http://127.0.0.1:" + wireMockPort + "/large2.js";

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://127.0.0.1:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("jsUrls", List.of(jsUrl1, jsUrl2)),
                null
        );

        ToolExecutionOutcome outcome = budgetTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.rawOutput()).contains("STOPPED: Aggregate payload budget exceeded");
        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("filesScanned")).isEqualTo(0);
    }

    @Test
    @DisplayName("Per-file payload limit skips oversized file and continues scanning subsequent files")
    void continuesScanningRemainingFilesWhenSingleFileExceedsLimit() throws Exception {
        PinnedHttpClient perFileClient = new PinnedHttpClient(policyEngine) {
            private int callCount = 0;

            @Override
            public PinnedProbeResult executeWithRedirects(
                    URI initialUri,
                    InetAddress initialIp,
                    boolean followRedirects,
                    SessionMode mode,
                    ScopeAsset scopeAsset,
                    long maxWireBytes,
                    long maxDecompressedBytes,
                    int readTimeoutMs,
                    AggregatePayloadBudget aggregateBudget
            ) throws IOException, PolicyViolationException {
                callCount++;
                if (callCount == 1) {
                    // First file exceeds single-file limit (not aggregate budget)
                    throw new PayloadLimitExceededException("Wire payload limit exceeded for single file (1048577 > 1048576)");
                }
                // Second file succeeds and contains secret
                String validJs = "const awsKey = \"AKIA1234567890ABCDEF\";";
                return new PinnedProbeResult(
                        initialUri.toString(),
                        200,
                        "HTTP/1.1",
                        Map.of("content-type", "application/javascript"),
                        List.of(),
                        List.of(),
                        validJs,
                        validJs.getBytes(StandardCharsets.UTF_8)
                );
            }
        };

        JsSecretsScannerTool perFileTool = new JsSecretsScannerTool(perFileClient, policyEngine, toolExecutionRepo, toolResultRepo, hostRateLimiter);

        String jsUrl1 = "http://127.0.0.1:" + wireMockPort + "/oversized.js";
        String jsUrl2 = "http://127.0.0.1:" + wireMockPort + "/valid.js";

        ToolExecutionContext context = new ToolExecutionContext(
                UUID.randomUUID(),
                UUID.randomUUID(),
                "http://127.0.0.1:" + wireMockPort,
                SessionMode.LOCAL,
                localScopeAsset,
                Map.of("jsUrls", List.of(jsUrl1, jsUrl2)),
                null
        );

        ToolExecutionOutcome outcome = perFileTool.execute(context);
        assertThat(outcome.hasErrors()).isFalse();
        assertThat(outcome.rawOutput()).contains("SKIPPED (File payload limit exceeded)");

        Map<String, Object> data = outcome.parsedData();
        assertThat(data.get("filesScanned")).isEqualTo(1);
        assertThat(data.get("totalSecretsFound")).isEqualTo(1);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> findings = (List<Map<String, Object>>) data.get("findings");
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).get("secretType")).isEqualTo("AWS Access Key ID");
    }

    private static int findFreeAllowedPort() {
        for (int port : List.of(8080, 8443, 8000, 3000, 5000)) {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress("127.0.0.1", port));
                return port;
            } catch (IOException ignored) {
            }
        }
        throw new IllegalStateException("No allowed test port free");
    }
}
