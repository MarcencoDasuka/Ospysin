package com.ospysin.tools.analysis;

import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.observations.SeverityHeuristic;
import com.ospysin.shared.error.InvalidParam;
import com.ospysin.shared.error.ResourceNotFoundException;
import com.ospysin.shared.error.ValidationException;
import com.ospysin.tools.ObservationDraft;
import com.ospysin.tools.OspysinTool;
import com.ospysin.tools.ToolExecutionContext;
import com.ospysin.tools.ToolExecutionOutcome;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tool #10: Security Headers Evaluation Score offline analytical tool (security_headers_score).
 * Purely offline evaluation of HTTP security headers previously captured by a completed http_headers step.
 * Performs zero network I/O and enforces strict BOLA session isolation.
 */
@Component
public class SecurityHeadersScoreTool implements OspysinTool {

    public static final String TOOL_ID = "security_headers_score";
    private static final Pattern MAX_AGE_PATTERN = Pattern.compile("max-age\\s*=\\s*(\\d+)", Pattern.CASE_INSENSITIVE);

    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;

    @Autowired
    public SecurityHeadersScoreTool(ToolExecutionRepository toolExecutionRepository,
                                    ToolResultRepository toolResultRepository) {
        this.toolExecutionRepository = Objects.requireNonNull(toolExecutionRepository, "toolExecutionRepository must not be null");
        this.toolResultRepository = Objects.requireNonNull(toolResultRepository, "toolResultRepository must not be null");
    }

    @Override
    public String getToolId() {
        return TOOL_ID;
    }

    @Override
    public void validateParams(Map<String, Object> params) throws ValidationException {
        if (params == null || !params.containsKey("stepId") || params.get("stepId") == null
                || params.get("stepId").toString().trim().isEmpty()) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId is required and must be a valid UUID"))
            );
        }

        try {
            UUID.fromString(params.get("stepId").toString().trim());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId must be a valid UUID"))
            );
        }
    }

    @Override
    public ToolExecutionOutcome execute(ToolExecutionContext context) throws Exception {
        Object stepIdVal = context.inputParams().get("stepId");
        if (stepIdVal == null || stepIdVal.toString().trim().isEmpty()) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId is required and must be a valid UUID"))
            );
        }

        UUID stepUuid;
        try {
            stepUuid = UUID.fromString(stepIdVal.toString().trim());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "stepId must be a valid UUID"))
            );
        }

        // 1. Fetch referenced step
        ToolExecution execution = toolExecutionRepository.findById(stepUuid)
                .orElseThrow(() -> new ResourceNotFoundException("Step not found: " + stepUuid));

        // 2. Strict BOLA Session Ownership Guard
        if (!execution.getSession().getId().equals(context.sessionId())) {
            throw new ResourceNotFoundException("Step not found: " + stepUuid);
        }

        // 3. Prerequisite Tool & Completion Status Verification
        if (execution.getStatus() != ExecutionStatus.COMPLETED || !"http_headers".equals(execution.getToolId())) {
            throw new ValidationException(
                    "Validation error for " + TOOL_ID,
                    List.of(new InvalidParam("stepId", "Referenced step must be a completed http_headers execution"))
            );
        }

        // 4. Fetch ToolResult
        ToolResult httpHeadersResult = toolResultRepository.findByExecutionId(stepUuid)
                .orElseThrow(() -> new ResourceNotFoundException("Tool result not found for step: " + stepUuid));

        // 5. Extract Normalized Headers Map
        Map<String, String> headers = extractNormalizedHeaders(httpHeadersResult.getParsedData());

        // 6. Evaluate the 6 OWASP Security Headers (0-100 score)
        int score = 0;
        List<String> presentHeaders = new ArrayList<>();
        List<String> missingHeaders = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        List<Map<String, Object>> breakdown = new ArrayList<>();

        // 1. Strict-Transport-Security (25 pts)
        if (headers.containsKey("strict-transport-security")) {
            String hstsVal = headers.get("strict-transport-security");
            Matcher m = MAX_AGE_PATTERN.matcher(hstsVal);
            long maxAge = -1;
            if (m.find()) {
                try {
                    maxAge = Long.parseLong(m.group(1));
                } catch (NumberFormatException ignored) {}
            }

            if (maxAge >= 10886400L) { // 18 weeks or higher
                score += 25;
                presentHeaders.add("Strict-Transport-Security");
                breakdown.add(buildBreakdown("Strict-Transport-Security", 25, 25, "PASS", "HSTS active with max-age >= 10886400s"));
            } else if (maxAge > 0L) {
                score += 15;
                presentHeaders.add("Strict-Transport-Security");
                recommendations.add("Increase Strict-Transport-Security max-age to at least 31536000 seconds (1 year).");
                breakdown.add(buildBreakdown("Strict-Transport-Security", 15, 25, "WARNING", "HSTS max-age is short (" + maxAge + "s)"));
            } else {
                missingHeaders.add("Strict-Transport-Security");
                recommendations.add("Configure Strict-Transport-Security with max-age of at least 31536000 seconds and includeSubDomains.");
                breakdown.add(buildBreakdown("Strict-Transport-Security", 0, 25, "FAIL", "HSTS max-age is 0 or unparseable"));
            }
        } else {
            missingHeaders.add("Strict-Transport-Security");
            recommendations.add("Enable Strict-Transport-Security (HSTS) with max-age of at least 31536000 seconds and includeSubDomains.");
            breakdown.add(buildBreakdown("Strict-Transport-Security", 0, 25, "MISSING", "Strict-Transport-Security header is missing"));
        }

        // 2. Content-Security-Policy (25 pts)
        if (headers.containsKey("content-security-policy")) {
            String cspVal = headers.get("content-security-policy").toLowerCase(Locale.ROOT);
            boolean hasUnsafe = cspVal.contains("unsafe-inline") || cspVal.contains("unsafe-eval");
            if (!hasUnsafe) {
                score += 25;
                presentHeaders.add("Content-Security-Policy");
                breakdown.add(buildBreakdown("Content-Security-Policy", 25, 25, "PASS", "Content-Security-Policy enforced without unsafe directives"));
            } else {
                score += 15;
                presentHeaders.add("Content-Security-Policy");
                recommendations.add("Eliminate 'unsafe-inline' and 'unsafe-eval' from Content-Security-Policy to mitigate Cross-Site Scripting (XSS).");
                breakdown.add(buildBreakdown("Content-Security-Policy", 15, 25, "WARNING", "Content-Security-Policy contains unsafe-inline or unsafe-eval"));
            }
        } else {
            missingHeaders.add("Content-Security-Policy");
            recommendations.add("Define a restrictive Content-Security-Policy to mitigate Cross-Site Scripting (XSS).");
            breakdown.add(buildBreakdown("Content-Security-Policy", 0, 25, "MISSING", "Content-Security-Policy header is missing"));
        }

        // 3. X-Content-Type-Options (15 pts)
        if (headers.containsKey("x-content-type-options")
                && headers.get("x-content-type-options").toLowerCase(Locale.ROOT).contains("nosniff")) {
            score += 15;
            presentHeaders.add("X-Content-Type-Options");
            breakdown.add(buildBreakdown("X-Content-Type-Options", 15, 15, "PASS", "X-Content-Type-Options is set to 'nosniff'"));
        } else {
            missingHeaders.add("X-Content-Type-Options");
            recommendations.add("Set X-Content-Type-Options header to 'nosniff' to prevent MIME-sniffing attacks.");
            String status = headers.containsKey("x-content-type-options") ? "FAIL" : "MISSING";
            breakdown.add(buildBreakdown("X-Content-Type-Options", 0, 15, status, "X-Content-Type-Options is missing or not 'nosniff'"));
        }

        // 4. X-Frame-Options (15 pts)
        String xfo = headers.get("x-frame-options");
        boolean xfoValid = xfo != null && (xfo.toUpperCase(Locale.ROOT).contains("DENY") || xfo.toUpperCase(Locale.ROOT).contains("SAMEORIGIN"));
        boolean cspFrameAncestors = headers.containsKey("content-security-policy")
                && headers.get("content-security-policy").toLowerCase(Locale.ROOT).contains("frame-ancestors");

        if (xfoValid || cspFrameAncestors) {
            score += 15;
            presentHeaders.add("X-Frame-Options");
            String detail = xfoValid ? "X-Frame-Options is set to " + xfo.trim() : "Clickjacking defense enforced via CSP frame-ancestors";
            breakdown.add(buildBreakdown("X-Frame-Options", 15, 15, "PASS", detail));
        } else {
            missingHeaders.add("X-Frame-Options");
            recommendations.add("Configure X-Frame-Options to 'DENY' or 'SAMEORIGIN' (or define CSP frame-ancestors) to defend against clickjacking.");
            String status = headers.containsKey("x-frame-options") ? "FAIL" : "MISSING";
            breakdown.add(buildBreakdown("X-Frame-Options", 0, 15, status, "Clickjacking protection is missing"));
        }

        // 5. Referrer-Policy (10 pts)
        if (headers.containsKey("referrer-policy")
                && !headers.get("referrer-policy").toLowerCase(Locale.ROOT).contains("unsafe-url")
                && !headers.get("referrer-policy").trim().isEmpty()) {
            score += 10;
            presentHeaders.add("Referrer-Policy");
            breakdown.add(buildBreakdown("Referrer-Policy", 10, 10, "PASS", "Referrer-Policy is set to " + headers.get("referrer-policy").trim()));
        } else {
            missingHeaders.add("Referrer-Policy");
            recommendations.add("Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.");
            String status = headers.containsKey("referrer-policy") ? "FAIL" : "MISSING";
            breakdown.add(buildBreakdown("Referrer-Policy", 0, 10, status, "Referrer-Policy is missing or set to unsafe-url"));
        }

        // 6. Permissions-Policy (10 pts)
        if (headers.containsKey("permissions-policy") && !headers.get("permissions-policy").trim().isEmpty()) {
            score += 10;
            presentHeaders.add("Permissions-Policy");
            breakdown.add(buildBreakdown("Permissions-Policy", 10, 10, "PASS", "Permissions-Policy header is configured"));
        } else {
            missingHeaders.add("Permissions-Policy");
            recommendations.add("Configure Permissions-Policy header to control browser features and sensitive device APIs.");
            breakdown.add(buildBreakdown("Permissions-Policy", 0, 10, "MISSING", "Permissions-Policy header is missing"));
        }

        // Letter grade calculation
        String grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";

        // Observations based on security posture
        List<ObservationDraft> observations = new ArrayList<>();
        if (score < 50) {
            observations.add(new ObservationDraft(
                    "SECURITY_SCORE",
                    "Weak HTTP security header posture: score " + score + "/100 (Grade " + grade + ")",
                    SeverityHeuristic.HIGH
            ));
        } else if (score < 80) {
            observations.add(new ObservationDraft(
                    "SECURITY_SCORE",
                    "Moderate HTTP security header posture: score " + score + "/100 (Grade " + grade + ")",
                    SeverityHeuristic.MEDIUM
            ));
        } else {
            observations.add(new ObservationDraft(
                    "SECURITY_SCORE",
                    "Strong HTTP security header posture: score " + score + "/100 (Grade " + grade + ")",
                    SeverityHeuristic.INFO
            ));
        }

        Map<String, Object> parsedData = new LinkedHashMap<>();
        parsedData.put("score", score);
        parsedData.put("grade", grade);
        parsedData.put("missingHeaders", missingHeaders);
        parsedData.put("presentHeaders", presentHeaders);
        parsedData.put("recommendations", recommendations);
        parsedData.put("breakdown", breakdown);
        parsedData.put("evaluatedStepId", stepUuid.toString());

        String rawOutput = buildRawOutput(score, grade, presentHeaders, missingHeaders, recommendations);

        return new ToolExecutionOutcome(
                rawOutput,
                parsedData,
                score,
                false,
                observations
        );
    }

    private Map<String, String> extractNormalizedHeaders(Map<String, Object> parsedData) {
        Map<String, String> headers = new HashMap<>();
        if (parsedData != null && parsedData.get("headers") instanceof Map<?, ?> rawMap) {
            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    headers.put(entry.getKey().toString().toLowerCase(Locale.ROOT), entry.getValue().toString());
                }
            }
        }
        return headers;
    }

    private Map<String, Object> buildBreakdown(String header, int score, int maxScore, String status, String details) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("header", header);
        entry.put("score", score);
        entry.put("maxScore", maxScore);
        entry.put("status", status);
        entry.put("details", details);
        return entry;
    }

    private String buildRawOutput(int score, String grade, List<String> present, List<String> missing, List<String> recs) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== HTTP Security Headers Score Report ===\n");
        sb.append("Overall Security Score: ").append(score).append("/100\n");
        sb.append("Letter Grade:           ").append(grade).append("\n\n");

        sb.append("--- Present Headers (").append(present.size()).append(") ---\n");
        if (present.isEmpty()) {
            sb.append("None\n");
        } else {
            for (String h : present) {
                sb.append("  [+] ").append(h).append("\n");
            }
        }

        sb.append("\n--- Missing Headers (").append(missing.size()).append(") ---\n");
        if (missing.isEmpty()) {
            sb.append("None (All recommended headers configured!)\n");
        } else {
            for (String h : missing) {
                sb.append("  [-] ").append(h).append("\n");
            }
        }

        sb.append("\n--- Actionable Recommendations (").append(recs.size()).append(") ---\n");
        if (recs.isEmpty()) {
            sb.append("No immediate hardening actions required.\n");
        } else {
            for (int i = 0; i < recs.size(); i++) {
                sb.append("  ").append(i + 1).append(". ").append(recs.get(i)).append("\n");
            }
        }

        return sb.toString();
    }
}
