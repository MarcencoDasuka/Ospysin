package com.ospysin.findings;

import com.ospysin.execution.ExecutionStatus;
import com.ospysin.execution.ToolExecution;
import com.ospysin.execution.ToolExecutionRepository;
import com.ospysin.execution.ToolResult;
import com.ospysin.execution.ToolResultRepository;
import com.ospysin.findings.dto.EvidenceResponse;
import com.ospysin.findings.dto.FindingResponse;
import com.ospysin.findings.dto.SessionObservationResponse;
import com.ospysin.sessions.AuditSession;
import com.ospysin.sessions.AuditSessionRepository;
import com.ospysin.shared.error.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class SessionReportService {

    private final AuditSessionRepository auditSessionRepository;
    private final ToolExecutionRepository toolExecutionRepository;
    private final ToolResultRepository toolResultRepository;
    private final FindingTxService findingTxService;

    /**
     * Generates a completely standalone, self-contained offline HTML report with inline CSS and print styles.
     */
    @Transactional(readOnly = true)
    public String generateStandaloneHtmlReport(UUID sessionId) {
        AuditSession session = auditSessionRepository.findById(sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found: " + sessionId));

        List<ToolExecution> executions = toolExecutionRepository.findBySessionIdOrderByCreatedAtAsc(sessionId);

        // Security headers score
        String headersScoreStr = "N/A";
        for (ToolExecution exec : executions) {
            if ("security_headers_score".equals(exec.getToolId()) && exec.getStatus() == ExecutionStatus.COMPLETED) {
                Optional<ToolResult> resOpt = toolResultRepository.findByExecutionId(exec.getId());
                if (resOpt.isPresent() && resOpt.get().getScore() != null) {
                    headersScoreStr = resOpt.get().getScore() + "/100";
                }
            }
        }

        // Findings
        List<FindingResponse> allFindings = findingTxService.getFindings(sessionId);

        long rejectedCount = allFindings.stream().filter(f -> f.status() == FindingStatus.REJECTED).count();
        long falsePositiveCount = allFindings.stream().filter(f -> f.status() == FindingStatus.FALSE_POSITIVE).count();

        // Active / Reportable findings
        List<FindingResponse> activeFindings = allFindings.stream()
                .filter(f -> f.status() == FindingStatus.OPEN || f.status() == FindingStatus.CONFIRMED)
                .sorted(Comparator.comparingInt((FindingResponse f) -> severityRank(f.severity()))
                        .thenComparing(FindingResponse::createdAt))
                .toList();

        // Severity Breakdown
        Map<FindingSeverity, Long> severityCounts = new EnumMap<>(FindingSeverity.class);
        for (FindingSeverity s : FindingSeverity.values()) {
            severityCounts.put(s, 0L);
        }
        for (FindingResponse f : activeFindings) {
            severityCounts.put(f.severity(), severityCounts.getOrDefault(f.severity(), 0L) + 1);
        }

        // Excluded findings (REJECTED and FALSE_POSITIVE) for Appendix
        List<FindingResponse> excludedFindings = allFindings.stream()
                .filter(f -> f.status() == FindingStatus.REJECTED || f.status() == FindingStatus.FALSE_POSITIVE)
                .sorted(Comparator.comparing(FindingResponse::updatedAt))
                .toList();

        // Automated observations
        List<SessionObservationResponse> observations = findingTxService.getSessionObservations(sessionId);

        return buildHtmlDocument(session, executions, headersScoreStr, activeFindings, severityCounts,
                rejectedCount, falsePositiveCount, observations, excludedFindings);
    }

    private static int severityRank(FindingSeverity severity) {
        if (severity == null) return 99;
        return switch (severity) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case INFO -> 4;
        };
    }

    public static String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String buildHtmlDocument(
            AuditSession session,
            List<ToolExecution> executions,
            String headersScoreStr,
            List<FindingResponse> activeFindings,
            Map<FindingSeverity, Long> severityCounts,
            long rejectedCount,
            long falsePositiveCount,
            List<SessionObservationResponse> observations,
            List<FindingResponse> excludedFindings
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n");
        sb.append("<html lang=\"en\">\n<head>\n");
        sb.append("<meta charset=\"UTF-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("<title>Security Audit Report - ").append(escapeHtml(session.getTargetUrl())).append("</title>\n");
        sb.append("<style>\n");
        sb.append("""
            :root {
                --bg-main: #020617;
                --bg-card: #0f172a;
                --bg-subtle: #1e293b;
                --border-color: #334155;
                --text-main: #f8fafc;
                --text-muted: #94a3b8;
                --text-accent: #38bdf8;
                --sev-critical: #ef4444;
                --sev-high: #f97316;
                --sev-medium: #f59e0b;
                --sev-low: #38bdf8;
                --sev-info: #64748b;
                --badge-bg: #1e293b;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background-color: var(--bg-main);
                color: var(--text-main);
                line-height: 1.6;
                padding: 2.5rem 1.5rem;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
            }
            header {
                border-bottom: 2px solid var(--border-color);
                padding-bottom: 1.5rem;
                margin-bottom: 2rem;
            }
            .brand {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 0.5rem;
            }
            .brand h1 {
                font-size: 1.75rem;
                font-weight: 800;
                letter-spacing: -0.025em;
                color: var(--text-accent);
            }
            .report-badge {
                font-size: 0.75rem;
                font-family: monospace;
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                background: var(--bg-subtle);
                border: 1px solid var(--border-color);
                color: var(--text-muted);
            }
            .subtitle {
                color: var(--text-muted);
                font-size: 0.875rem;
            }
            section {
                margin-bottom: 2.5rem;
            }
            h2 {
                font-size: 1.25rem;
                font-weight: 700;
                margin-bottom: 1rem;
                padding-bottom: 0.5rem;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }
            .grid-meta {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 1rem;
            }
            .meta-card {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                padding: 1rem;
                border-radius: 6px;
            }
            .meta-label {
                font-size: 0.75rem;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                font-weight: 600;
                margin-bottom: 0.25rem;
            }
            .meta-value {
                font-size: 0.95rem;
                font-family: monospace;
                font-weight: 600;
                word-break: break-all;
            }
            .grid-severity {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 0.75rem;
            }
            .sev-card {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                padding: 0.85rem;
                border-radius: 6px;
                text-align: center;
            }
            .sev-card.critical { border-top: 4px solid var(--sev-critical); }
            .sev-card.high { border-top: 4px solid var(--sev-high); }
            .sev-card.medium { border-top: 4px solid var(--sev-medium); }
            .sev-card.low { border-top: 4px solid var(--sev-low); }
            .sev-card.info { border-top: 4px solid var(--sev-info); }
            .sev-count {
                font-size: 1.75rem;
                font-weight: 800;
                line-height: 1.2;
            }
            .sev-name {
                font-size: 0.7rem;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--text-muted);
            }
            .finding-card {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                padding: 1.25rem;
                margin-bottom: 1.25rem;
                page-break-inside: avoid;
            }
            .finding-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                flex-wrap: wrap;
                gap: 0.5rem;
                margin-bottom: 0.75rem;
            }
            .finding-title {
                font-size: 1.1rem;
                font-weight: 700;
                color: var(--text-main);
            }
            .badges {
                display: flex;
                gap: 0.5rem;
                align-items: center;
            }
            .badge {
                font-size: 0.7rem;
                font-family: monospace;
                font-weight: 700;
                padding: 0.2rem 0.5rem;
                border-radius: 4px;
                text-transform: uppercase;
            }
            .badge-critical { background: #450a0a; color: #fca5a5; border: 1px solid var(--sev-critical); }
            .badge-high { background: #431407; color: #fdba74; border: 1px solid var(--sev-high); }
            .badge-medium { background: #451a03; color: #fde68a; border: 1px solid var(--sev-medium); }
            .badge-low { background: #082f49; color: #bae6fd; border: 1px solid var(--sev-low); }
            .badge-info { background: #1e293b; color: #cbd5e1; border: 1px solid var(--sev-info); }
            .badge-status { background: #1e293b; color: #94a3b8; border: 1px solid var(--border-color); }
            .finding-body {
                font-size: 0.9rem;
                color: #cbd5e1;
                margin-bottom: 1rem;
                white-space: pre-wrap;
            }
            .remediation-box {
                background: #022c22;
                border: 1px solid #065f46;
                color: #a7f3d0;
                padding: 0.75rem 1rem;
                border-radius: 4px;
                font-size: 0.85rem;
                margin-bottom: 1rem;
            }
            .remediation-box strong {
                display: block;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 0.25rem;
                color: #34d399;
            }
            .evidence-section {
                margin-top: 1rem;
                border-top: 1px dashed var(--border-color);
                padding-top: 0.75rem;
            }
            .evidence-header {
                font-size: 0.75rem;
                text-transform: uppercase;
                color: var(--text-muted);
                font-weight: 700;
                margin-bottom: 0.5rem;
            }
            .evidence-item {
                background: #020617;
                border: 1px solid var(--border-color);
                border-radius: 4px;
                padding: 0.75rem;
                margin-bottom: 0.5rem;
            }
            .evidence-meta {
                font-size: 0.75rem;
                font-family: monospace;
                color: var(--text-accent);
                margin-bottom: 0.35rem;
            }
            pre {
                background: #020617;
                padding: 0.5rem;
                border-radius: 4px;
                overflow-x: auto;
                font-size: 0.8rem;
                font-family: Consolas, "Courier New", monospace;
                color: #e2e8f0;
                white-space: pre-wrap;
                word-break: break-all;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                font-size: 0.85rem;
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 6px;
                overflow: hidden;
            }
            th, td {
                padding: 0.65rem 0.85rem;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
            }
            th {
                background: var(--bg-subtle);
                color: var(--text-muted);
                font-weight: 600;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            tr:last-child td { border-bottom: none; }
            .empty-state {
                padding: 2rem;
                text-align: center;
                background: var(--bg-card);
                border: 1px dashed var(--border-color);
                border-radius: 6px;
                color: var(--text-muted);
                font-size: 0.9rem;
            }
            .curation-note {
                font-size: 0.8rem;
                color: var(--text-muted);
                margin-top: 0.5rem;
                font-style: italic;
            }
            @media print {
                body {
                    background: #ffffff !important;
                    color: #000000 !important;
                    padding: 0 !important;
                }
                .container { max-width: 100% !important; }
                .meta-card, .sev-card, .finding-card, table, .evidence-item {
                    background: #ffffff !important;
                    color: #000000 !important;
                    border: 1px solid #cccccc !important;
                    box-shadow: none !important;
                }
                h1, h2, .finding-title { color: #000000 !important; }
                .remediation-box {
                    background: #f0fdf4 !important;
                    color: #14532d !important;
                    border: 1px solid #bbf7d0 !important;
                }
                .badge { border: 1px solid #888888 !important; color: #000000 !important; }
                pre { background: #f8fafc !important; color: #000000 !important; border: 1px solid #e2e8f0 !important; }
                .finding-card { page-break-inside: avoid !important; }
            }
        """);
        sb.append("</style>\n</head>\n<body>\n");
        sb.append("<div class=\"container\">\n");

        // Header
        sb.append("<header>\n");
        sb.append("  <div class=\"brand\">\n");
        sb.append("    <h1>OSINT &amp; Security Audit Report</h1>\n");
        sb.append("    <span class=\"report-badge\">Ospysin Platform v0.1</span>\n");
        sb.append("  </div>\n");
        sb.append("  <div class=\"subtitle\">Generated independently from immutable forensic execution ledger</div>\n");
        sb.append("</header>\n");

        // 1. Executive Summary
        sb.append("<section id=\"executive-summary\">\n");
        sb.append("  <h2>1. Executive Summary &amp; Scope Authorization</h2>\n");
        sb.append("  <div class=\"grid-meta\">\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Target URL</div><div class=\"meta-value\">").append(escapeHtml(session.getTargetUrl())).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Inspection Mode</div><div class=\"meta-value\">").append(escapeHtml(session.getMode() != null ? session.getMode().name() : "N/A")).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Session State</div><div class=\"meta-value\">").append(escapeHtml(session.getState() != null ? session.getState().name() : "N/A")).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Security Headers Score</div><div class=\"meta-value\">").append(escapeHtml(headersScoreStr)).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Created At</div><div class=\"meta-value\">").append(escapeHtml(String.valueOf(session.getCreatedAt()))).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Total Execution Steps</div><div class=\"meta-value\">").append(executions.size()).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Scope Ack Version</div><div class=\"meta-value\">").append(escapeHtml(session.getScopeAckVersion() != null ? session.getScopeAckVersion() : "N/A")).append("</div></div>\n");
        sb.append("    <div class=\"meta-card\"><div class=\"meta-label\">Scope SHA-256 Hash</div><div class=\"meta-value\">").append(escapeHtml(session.getScopeAckHash() != null ? session.getScopeAckHash() : "N/A")).append("</div></div>\n");
        sb.append("  </div>\n");
        sb.append("</section>\n");

        // 2. Severity Breakdown
        sb.append("<section id=\"severity-breakdown\">\n");
        sb.append("  <h2>2. Severity Distribution</h2>\n");
        sb.append("  <div class=\"grid-severity\">\n");
        sb.append("    <div class=\"sev-card critical\"><div class=\"sev-count\" style=\"color: var(--sev-critical);\">").append(severityCounts.getOrDefault(FindingSeverity.CRITICAL, 0L)).append("</div><div class=\"sev-name\">Critical</div></div>\n");
        sb.append("    <div class=\"sev-card high\"><div class=\"sev-count\" style=\"color: var(--sev-high);\">").append(severityCounts.getOrDefault(FindingSeverity.HIGH, 0L)).append("</div><div class=\"sev-name\">High</div></div>\n");
        sb.append("    <div class=\"sev-card medium\"><div class=\"sev-count\" style=\"color: var(--sev-medium);\">").append(severityCounts.getOrDefault(FindingSeverity.MEDIUM, 0L)).append("</div><div class=\"sev-name\">Medium</div></div>\n");
        sb.append("    <div class=\"sev-card low\"><div class=\"sev-count\" style=\"color: var(--sev-low);\">").append(severityCounts.getOrDefault(FindingSeverity.LOW, 0L)).append("</div><div class=\"sev-name\">Low</div></div>\n");
        sb.append("    <div class=\"sev-card info\"><div class=\"sev-count\" style=\"color: var(--sev-info);\">").append(severityCounts.getOrDefault(FindingSeverity.INFO, 0L)).append("</div><div class=\"sev-name\">Info</div></div>\n");
        sb.append("  </div>\n");
        if (rejectedCount > 0 || falsePositiveCount > 0) {
            sb.append("  <div class=\"curation-note\">Note: ").append(rejectedCount).append(" finding(s) rejected by operator, ")
                    .append(falsePositiveCount).append(" marked false-positive (excluded from active vulnerability count).</div>\n");
        }
        sb.append("</section>\n");

        // 3. Curated Findings & Evidence
        sb.append("<section id=\"curated-findings\">\n");
        sb.append("  <h2>3. Curated Findings &amp; Forensic Evidence (").append(activeFindings.size()).append(")</h2>\n");
        if (activeFindings.isEmpty()) {
            sb.append("  <div class=\"empty-state\">No active or confirmed findings were recorded for this audit session.</div>\n");
        } else {
            for (FindingResponse finding : activeFindings) {
                String sevClass = switch (finding.severity()) {
                    case CRITICAL -> "badge-critical";
                    case HIGH -> "badge-high";
                    case MEDIUM -> "badge-medium";
                    case LOW -> "badge-low";
                    case INFO -> "badge-info";
                };

                sb.append("  <div class=\"finding-card\">\n");
                sb.append("    <div class=\"finding-header\">\n");
                sb.append("      <div class=\"finding-title\">").append(escapeHtml(finding.title())).append("</div>\n");
                sb.append("      <div class=\"badges\">\n");
                sb.append("        <span class=\"badge ").append(sevClass).append("\">").append(escapeHtml(finding.severity().name())).append("</span>\n");
                sb.append("        <span class=\"badge badge-status\">").append(escapeHtml(finding.confidence() != null ? finding.confidence().name() : "TENTATIVE")).append("</span>\n");
                sb.append("        <span class=\"badge badge-status\">").append(escapeHtml(finding.status().name())).append("</span>\n");
                sb.append("      </div>\n");
                sb.append("    </div>\n");

                sb.append("    <div class=\"finding-body\">").append(escapeHtml(finding.description())).append("</div>\n");

                if (finding.remediation() != null && !finding.remediation().isBlank()) {
                    sb.append("    <div class=\"remediation-box\"><strong>Recommended Remediation</strong>")
                            .append(escapeHtml(finding.remediation())).append("</div>\n");
                }

                if (!finding.evidence().isEmpty()) {
                    sb.append("    <div class=\"evidence-section\">\n");
                    sb.append("      <div class=\"evidence-header\">Linked Forensic Evidence (").append(finding.evidence().size()).append(")</div>\n");
                    for (EvidenceResponse ev : finding.evidence()) {
                        sb.append("      <div class=\"evidence-item\">\n");
                        sb.append("        <div class=\"evidence-meta\">Source Tool: ").append(escapeHtml(ev.toolId() != null ? ev.toolId() : "execution"))
                                .append(" &bull; Captured: ").append(escapeHtml(String.valueOf(ev.createdAt()))).append("</div>\n");
                        sb.append("        <pre><code>").append(escapeHtml(ev.snippet())).append("</code></pre>\n");
                        sb.append("      </div>\n");
                    }
                    sb.append("    </div>\n");
                }
                sb.append("  </div>\n");
            }
        }
        sb.append("</section>\n");

        // 4. Automated Observations & Tool Execution Timeline
        sb.append("<section id=\"execution-timeline\">\n");
        sb.append("  <h2>4. Tool Execution Timeline (").append(executions.size()).append(")</h2>\n");
        if (executions.isEmpty()) {
            sb.append("  <div class=\"empty-state\">No tool executions recorded.</div>\n");
        } else {
            sb.append("  <table>\n");
            sb.append("    <thead><tr><th>Tool ID</th><th>Status</th><th>Duration</th><th>Started At</th><th>Ended At</th></tr></thead>\n");
            sb.append("    <tbody>\n");
            for (ToolExecution exec : executions) {
                String dur = exec.getDurationMs() != null ? exec.getDurationMs() + " ms" : "-";
                sb.append("      <tr>\n");
                sb.append("        <td><code>").append(escapeHtml(exec.getToolId())).append("</code></td>\n");
                sb.append("        <td>").append(escapeHtml(exec.getStatus().name())).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(dur)).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(String.valueOf(exec.getStartedAt()))).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(String.valueOf(exec.getEndedAt()))).append("</td>\n");
                sb.append("      </tr>\n");
            }
            sb.append("    </tbody>\n");
            sb.append("  </table>\n");
        }

        if (!observations.isEmpty()) {
            sb.append("  <h3 style=\"font-size: 1rem; margin-top: 1.5rem; margin-bottom: 0.75rem; color: var(--text-muted);\">Automated Observations (")
                    .append(observations.size()).append(")</h3>\n");
            sb.append("  <table>\n");
            sb.append("    <thead><tr><th>Category</th><th>Heuristic</th><th>Description</th><th>Detected At</th></tr></thead>\n");
            sb.append("    <tbody>\n");
            for (SessionObservationResponse obs : observations) {
                sb.append("      <tr>\n");
                sb.append("        <td><code>").append(escapeHtml(obs.category())).append("</code></td>\n");
                sb.append("        <td>").append(escapeHtml(obs.severityHeuristic() != null ? obs.severityHeuristic().name() : "INFO")).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(obs.description())).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(String.valueOf(obs.detectedAt()))).append("</td>\n");
                sb.append("      </tr>\n");
            }
            sb.append("    </tbody>\n");
            sb.append("  </table>\n");
        }
        sb.append("</section>\n");
 
        // 5. Rejected Findings & False Positive Log (Appendix)
        if (!excludedFindings.isEmpty()) {
            sb.append("<section id=\"rejected-findings-appendix\">\n");
            sb.append("  <h2>5. Rejected Findings &amp; False Positive Log (Appendix)</h2>\n");
            sb.append("  <table>\n");
            sb.append("    <thead><tr><th>Title</th><th>Severity</th><th>Status</th><th>Operator Justification / Reason</th><th>Updated At</th></tr></thead>\n");
            sb.append("    <tbody>\n");
            for (FindingResponse f : excludedFindings) {
                String justification = f.rejectionReason() != null && !f.rejectionReason().isBlank()
                        ? f.rejectionReason()
                        : (f.status() == FindingStatus.FALSE_POSITIVE ? "Flagged as False Positive" : "-");
                sb.append("      <tr>\n");
                sb.append("        <td><strong>").append(escapeHtml(f.title())).append("</strong></td>\n");
                sb.append("        <td>").append(escapeHtml(f.severity().name())).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(f.status().name())).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(justification)).append("</td>\n");
                sb.append("        <td>").append(escapeHtml(String.valueOf(f.updatedAt()))).append("</td>\n");
                sb.append("      </tr>\n");
            }
            sb.append("    </tbody>\n");
            sb.append("  </table>\n");
            sb.append("</section>\n");
        }

        sb.append("</div>\n");
        sb.append("</body>\n</html>");

        return sb.toString();
    }
}
