# Phase 17: Findings Curation, Evidence Linking & Standalone HTML/PDF Reporting — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-17-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-17-snapshot.md`  

---

## Remediation Checklist

- [x] **P17-01 [HIGH] [INTEGRITY / SESSION STATE GUARD]**: Enforce `SessionState.ABORTED` Guard in `FindingTxService.attachEvidence()`:
  - Fetched `AuditSession` using `auditSessionRepository.findById(sessionId)` instead of simple existence check in `FindingTxService.attachEvidence()`.
  - Added explicit state check: `if (session.getState() == SessionState.ABORTED) throw new ConflictException("Cannot attach evidence in an ABORTED session");`.
  - Added regression test `testAbortedSessionBlocksFindingCreationUpdateAndEvidenceAttachment` in `FindingCurationAndReportIT.java` verifying `409 Conflict` on create finding, update finding, and attach evidence.
- [x] **P17-02 [MEDIUM] [METRIC CONSISTENCY & STATE MACHINE INTEGRITY]**: Exclude both `REJECTED` and `FALSE_POSITIVE` from active finding counts across backend and frontend:
  - In `FindingRepository.java`: updated `@Query countFindingsBySessionIds` to `WHERE f.session.id IN :sessionIds AND f.status NOT IN (com.ospysin.findings.FindingStatus.REJECTED, com.ospysin.findings.FindingStatus.FALSE_POSITIVE)` and added `countBySessionIdAndStatusNotIn(UUID sessionId, Collection<FindingStatus> excludedStatuses)`.
  - In `AuditSessionService.java` and `AuditSessionTxService.java`: updated `getSession`, `completeSession`, and `abortSession` to invoke `countBySessionIdAndStatusNotIn(id, List.of(FindingStatus.REJECTED, FindingStatus.FALSE_POSITIVE))`.
  - In `frontend/src/stores/workspace.ts`, `SessionWorkspaceView.vue`, and `FindingsDrawer.vue`: updated `activeFindingsCount` and `activeFindings` to filter `f.status !== 'REJECTED' && f.status !== 'FALSE_POSITIVE'`.
  - Added regression tests in `FindingCurationAndReportIT.java`, `workspace.store.spec.ts`, and `SessionWorkspaceView.spec.ts` verifying that transitioning to `FALSE_POSITIVE` decrements active finding counts.
- [x] **P17-03 [MEDIUM] [FRONTEND STATE ISOLATION & ACTION GUARDS]**: Reset transient form state on drawer close/session change and restrict evidence attachment button:
  - In `FindingsDrawer.vue`: added watcher on `[() => props.isOpen, () => currentSession.value?.id]` resetting `showCreateForm`, `formTitle`, `formDescription`, `formRemediation`, `rejectingFindingId`, `attachingEvidenceFindingId`, `rejectReasons`, and `evidenceSnippets`.
  - In `SessionWorkspaceView.vue`: ensured `isFindingsDrawerOpen.value = false` on `sessionId` change.
  - In `FindingsDrawer.vue`: bound `:disabled` on `+ Attach Evidence` to `!(activeStepDetail && activeStepDetail.status === 'COMPLETED' && (activeStepDetail.resultId || activeStepDetail.executionId))` with `disabled:opacity-40 disabled:cursor-not-allowed`.
  - Added regression tests in `SessionWorkspaceView.spec.ts` verifying drawer closing on route change, form state reset on close, and button disabling on running/incomplete steps.
- [x] **P17-04 [LOW] [REPORTING COMPLETENESS & AUDIT TRAIL]**: Render "5. Rejected Findings & False Positive Log (Appendix)" section in `SessionReportService.java`:
  - Segregated `excludedFindings` (`REJECTED` and `FALSE_POSITIVE`) and rendered Section 5 `<section id="rejected-findings-appendix">` with `<h2>5. Rejected Findings &amp; False Positive Log (Appendix)</h2>`.
  - Formatted an HTML table listing Title, Severity, Final Status, Auditor Justification / Rejection Reason, and Decision Date.
  - Enforced strict HTML escaping via `escapeHtml(...)` to eliminate any XSS vulnerability.
  - Added regression test `testRejectedAndFalsePositiveAppendixInReportHtml` in `FindingCurationAndReportIT.java` asserting Section 5 presence, column formatting, and strict XSS escaping.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 405/405 passed across all 51 test suites (`.\mvnw.cmd clean verify`):
  - `FindingCurationAndReportIT`: 15/15 passed.
  - All existing 390 core backend tests passed without regression.
  - JaCoCo instruction coverage gate met ($\ge 80\%$).
- **Frontend Unit & Component Tests:** 133/133 passed across 12 test suites (`npm.cmd test -- --run`):
  - `SessionWorkspaceView.spec.ts`: 30/30 passed.
  - `workspace.store.spec.ts`: 17/17 passed.
  - `SessionReportView.spec.ts`: 4/4 passed.
  - All existing 82 frontend tests passed.
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` completed in 1.71s with 0 diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-17-snapshot.md`.
