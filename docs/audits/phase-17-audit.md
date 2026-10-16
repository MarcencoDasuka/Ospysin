# Phase 17: Findings Curation, Evidence Linking & Standalone HTML/PDF Reporting — Architectural & Security Audit Report

**Date:** 2026-10-16  
**Audit Target:** `phase-17-snapshot.md` (`FindingTxService`, `SessionReportService`, `FindingRepository`, `AuditSessionService`, `AuditSessionTxService`, `FindingsDrawer.vue`, `SessionWorkspaceView.vue`, `SessionReportView.vue`, `FindingCurationAndReportIT`)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An adversarial security, integrity, and architectural audit of Phase 17 evaluated the findings curation, evidence linking, and standalone audit reporting subsystem:
1. **Findings Lifecycle & State Machine**: Promotion of automated observations to findings, manual finding creation, confidence defaults (`FIRM` vs `TENTATIVE`), allowed transitions (`OPEN -> CONFIRMED`, `OPEN -> FALSE_POSITIVE`, `OPEN -> REJECTED`, `CONFIRMED -> REJECTED`), terminal state immutability, mandatory rejection reasons, and BOLA cross-session containment.
2. **Forensic Evidence Linking**: Attachment of raw output snippets from completed tool executions (`ToolResult` / `ToolExecution`), ensuring multi-hop foreign key integrity and BOLA boundary enforcement across audit sessions.
3. **Session Metric Aggregation**: Synchronous tracking and projection of active `findingCount` on `AuditSession` responses, ensuring discarded false positives and rejected items do not distort executive metrics.
4. **Standalone Audit Report Generation**: Server-side zero-dependency HTML document builder in `SessionReportService.java` providing executive summary, scope acknowledgment hash and timestamp, active findings grouped by severity, evidence snippets, and printable CSS styling.
5. **Operator Workspace & Findings Drawer**: Interactive Vue 3 slide-over drawer (`FindingsDrawer.vue`), real-time badges in `SessionWorkspaceView.vue`, and iframe print-preview in `SessionReportView.vue`.

The audit identified 4 findings (1 High, 2 Medium, 1 Low). All 4 findings have been remediated and verified with **405 backend Maven tests** (0 failures, 0 errors, 0 skipped) and **133 frontend Vitest tests** (0 failures), with clean type-checking and production bundling (`vue-tsc --noEmit && vite build`).

---

## Detailed Findings & Remediations

### P17-01 [HIGH] [INTEGRITY / SESSION STATE GUARD]: Missing `SessionState.ABORTED` Guard in `FindingTxService.attachEvidence()`
- **Issue:**
  - While `createFinding` and `updateFinding` strictly verified that the enclosing audit session was not in `SessionState.ABORTED` (throwing `ConflictException("Cannot curate findings in an ABORTED session")`), `attachEvidence()` only performed `auditSessionRepository.existsById(sessionId)`.
  - As a result, operators or automated callers could attach evidence snippets to findings belonging to aborted audit sessions, violating the immutability invariant of aborted sessions.
- **Impact:** Violation of session immutability; evidence could be mutated in terminated audit sessions.
- **Remediation:**
  - Updated `FindingTxService.attachEvidence()` to load `AuditSession` via `auditSessionRepository.findById(sessionId)` and throw `ConflictException("Cannot attach evidence in an ABORTED session")` when `session.getState() == SessionState.ABORTED`.
  - Added regression test `testAbortedSessionBlocksFindingCreationUpdateAndEvidenceAttachment` in `FindingCurationAndReportIT.java`, asserting `409 Conflict` Problem Details on create finding, update finding, and attach evidence in aborted sessions.

---

### P17-02 [MEDIUM] [METRIC CONSISTENCY & STATE MACHINE INTEGRITY]: Active Finding Count Inconsistently Included `FALSE_POSITIVE` Findings
- **Issue:**
  - `FindingStatus.FALSE_POSITIVE` is a terminal status representing non-vulnerabilities or benign scanner anomalies.
  - However, `FindingRepository.countFindingsBySessionIds` and `countBySessionIdAndStatusNot(..., FindingStatus.REJECTED)` only filtered out `REJECTED`.
  - As a result, marking a finding as `FALSE_POSITIVE` kept the active `findingCount` incremented on `AuditSession` entity projections and session cards.
  - Additionally, frontend computed properties (`workspace.ts`, `SessionWorkspaceView.vue`, `FindingsDrawer.vue`) only filtered `f.status !== 'REJECTED'`.
- **Impact:** Distorted security posture metrics where discarded false alarms were counted as active vulnerabilities in dashboard cards and workspace counters.
- **Remediation:**
  - In `FindingRepository.java`: updated `@Query countFindingsBySessionIds` JPQL to `WHERE f.session.id IN :sessionIds AND f.status NOT IN (com.ospysin.findings.FindingStatus.REJECTED, com.ospysin.findings.FindingStatus.FALSE_POSITIVE)` and added `countBySessionIdAndStatusNotIn(UUID sessionId, Collection<FindingStatus> excludedStatuses)`.
  - In `AuditSessionService.java` and `AuditSessionTxService.java`: updated `getSession`, `completeSession`, and `abortSession` to call `countBySessionIdAndStatusNotIn(id, List.of(FindingStatus.REJECTED, FindingStatus.FALSE_POSITIVE))`.
  - In `frontend/src/stores/workspace.ts`, `SessionWorkspaceView.vue`, and `FindingsDrawer.vue`: updated `activeFindingsCount` and `activeFindings` to filter `f.status !== 'REJECTED' && f.status !== 'FALSE_POSITIVE'`.
  - Added regression tests in `FindingCurationAndReportIT.java`, `workspace.store.spec.ts`, and `SessionWorkspaceView.spec.ts` verifying that transitioning to `FALSE_POSITIVE` decrements active finding counts.

---

### P17-03 [MEDIUM] [FRONTEND STATE ISOLATION & ACTION GUARDS]: Transient Form State Leaked Across Drawer Close/Session Switch and Unrestricted Evidence Attachment Button
- **Issue:**
  - Closing `FindingsDrawer.vue` or navigating to another session left transient form values (`formTitle`, `formDescription`, `formRemediation`, `showCreateForm`), inline rejection reasons, and inline evidence snippets cached in component refs.
  - Navigating to another session route in `SessionWorkspaceView.vue` did not close the findings drawer.
  - In `FindingsDrawer.vue`, the `+ Attach Evidence` button was enabled whenever any step detail was active, even if the step was in `RUNNING` or `PENDING` status or lacked an execution/result ID.
- **Impact:** Accidental data leakage between distinct audit sessions and failed evidence submission attempts against in-progress steps.
- **Remediation:**
  - In `FindingsDrawer.vue`: added a multi-watcher on `[() => props.isOpen, () => currentSession.value?.id]` that invokes `closeCreateForm()`, resets `rejectingFindingId`, `attachingEvidenceFindingId`, `rejectReasons`, and `evidenceSnippets`.
  - In `SessionWorkspaceView.vue`: set `isFindingsDrawerOpen.value = false` inside `watch(sessionId, ...)`.
  - In `FindingsDrawer.vue`: updated the `:disabled` attribute on `+ Attach Evidence` to:
    `!(activeStepDetail && activeStepDetail.status === 'COMPLETED' && (activeStepDetail.resultId || activeStepDetail.executionId))` with appropriate disabled styles.
  - Added regression tests in `SessionWorkspaceView.spec.ts` verifying drawer closing on route change, form state reset on close, and button disabling on running/incomplete steps.

---

### P17-04 [LOW] [REPORTING COMPLETENESS & AUDIT TRAIL]: Missing Appendix for Rejected & False Positive Findings in Standalone Report
- **Issue:**
  - Per Screen 4 specifications (`docs/10-UI-UX-SPEC.md`), audit deliverables require an audit trail of rejected items and false positives so stakeholders can verify auditor decisions, justifications, and timestamps.
  - `SessionReportService.java` previously omitted `REJECTED` and `FALSE_POSITIVE` findings entirely from the generated HTML report.
- **Impact:** Omission of auditor justifications from executive deliverables, hindering peer review and governance compliance.
- **Remediation:**
  - In `SessionReportService.java`: segregated `excludedFindings` (`REJECTED` and `FALSE_POSITIVE`) and rendered Section 5 `<section id="rejected-findings-appendix">` titled `5. Rejected Findings & False Positive Log (Appendix)`.
  - Formatted an HTML table listing Title, Severity, Final Status, Auditor Justification / Rejection Reason, and Decision Date.
  - Enforced strict HTML escaping via `escapeHtml(...)` on all dynamic fields (titles, descriptions, rejection reasons) to prevent stored XSS injection.
  - Added regression test `testRejectedAndFalsePositiveAppendixInReportHtml` in `FindingCurationAndReportIT.java` asserting Section 5 presence, content formatting, and strict XSS escaping.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 405/405 passed across all 51 test suites (`.\mvnw.cmd clean verify`):
  - `FindingCurationAndReportIT`: 15/15 passed (observation promotion, manual finding creation, BOLA cross-session isolation, state machine transitions, mandatory rejection reasons, aborted session guards, false positive count decrement, Section 5 report appendix, and strict XSS falsification).
  - All existing 390 core backend tests passed without regression.
  - JaCoCo instruction coverage gate met ($\ge 80\%$).
- **Frontend Unit & Component Tests:** 133/133 passed across 12 test suites (`npm.cmd test -- --run`):
  - `SessionWorkspaceView.spec.ts`: 30/30 passed (drawer opening, observation promotion, manual creation, confirmation, rejection with reason, attach evidence, drawer reset on close/session switch, attach evidence button disabled on running step, false positive transition).
  - `workspace.store.spec.ts`: 17/17 passed (finding CRUD, evidence attachment, report HTML fetching, active count decrements on rejection and false positive).
  - `SessionReportView.spec.ts`: 4/4 passed (report iframe loading, error state, print action, back button).
  - All existing 82 frontend tests passed.
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` completed in 1.71s with 0 diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-17-snapshot.md`.
