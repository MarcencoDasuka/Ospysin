# Phase 12: Local LLM Advisory Integration — Architectural & Security Audit Report

**Date:** 2026-10-15  
**Audit Target:** `phase-12-snapshot.md` (Local Ollama Cybersecurity Advisory Integration, 1,450-Token Context Budgeter, Prompt Injection Delimiter Defense, Decoupled Transactions, and Right Panel Advisor UI)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An adversarial audit of the Phase 12 implementation identified 5 findings (1 High, 2 Medium, 2 Low) spanning fixed-point infinite loops in token truncation fallback, delimiter tag sanitization bypasses, missing session state and step status guards on commentary endpoints, un-fenced late LLM output broadcasts on aborted sessions, N+1 observation query anti-patterns, and orphaned loading spinners on SSE session termination or connection drops. All 5 findings have been remediated, verified, and validated across 116 frontend Vitest tests and 293 backend Maven tests (spanning unit, WireMock, and Testcontainers PostgreSQL integration suites), with clean production build bundling (`vue-tsc --noEmit && vite build`).

---

## Detailed Findings & Remediations

### P12-01 [HIGH] [VERIFIED BUG]: Fixed-Point Infinite Loop in `LlmContextBudgeter` Fallback Truncation
- **Issue:**
  - In `LlmContextBudgeter.java`, fallback truncation `while` loops in both `buildCommentPrompts` and `buildChatPrompts` attempted to iteratively shave payloads exceeding the 1,450-token budget ceiling.
  - However, on each loop iteration, the code took a percentage of the already-mutated string (85% and 80%) and re-appended the suffix `"\n... [TRUNCATED]"` (16 characters).
  - In `buildCommentPrompts`, at length `101`, `(int)(101 * 0.85) + 16 = 85 + 16 = 101`.
  - In `buildChatPrompts`, at length `76`, `(int)(76 * 0.80) + 16 = 60 + 16 = 76`.
  - Once reached, the string length remained unchanged indefinitely, causing worker and HTTP threads to spin in an infinite CPU loop if the budget remained exceeded.
- **Impact:** Thread exhaustion and worker starvation when processing unusually dense outputs or long session contexts.
- **Remediation:**
  - Refactored both `buildCommentPrompts` and `buildChatPrompts` to maintain an immutable reference to the un-suffixed base payload (`baseResultJson` / `baseObsSummary`) and decrement `rawLen` strictly monotonically:
    `rawLen = Math.max(30, Math.min(rawLen - 15, (int)(rawLen * 0.80)))`.
  - Added deterministic exit condition `if (rawLen == 30) break;`.
  - Added unit regression test in `LlmContextBudgeterTest` (`testDeterministicTerminationWithoutInfiniteLoopOnExtremeBudget`) verifying instant termination under extreme payload pressure.

---

### P12-02 [MEDIUM] [SECURITY VULNERABILITY]: Permissive Delimiter Tag Sanitization & Missing Previous Step Observation Sanitization
- **Issue:**
  - `LlmContextBudgeter.sanitizeUntrustedContent` previously used exact string matches (`<untrusted_tool_output>`, etc.), which failed to sanitize delimiter tags with trailing spaces or attributes (e.g. `</untrusted_tool_output >`, `< /untrusted_tool_output>`, `<audit_context id="1">`).
  - In `buildCommentPrompts`, `compactPreviousSteps` assembled observation strings from prior steps without passing through `sanitizeUntrustedContent`, allowing indirect prompt injection from telemetry discovered in previous steps.
  - In `formatStepResultJson`, heuristic observations were dropped if `parsedData` was present, hiding security findings from LLM context.
- **Impact:** Potential indirect prompt injection and compromised threat analysis quality.
- **Remediation:**
  - Upgraded delimiter regexes in `LlmContextBudgeter.java` to case-insensitive whitespace/attribute-tolerant patterns:
    `(?i)<\\s*/\\s*untrusted_tool_output\\b[^>]*>` and `(?i)<\\s*/\\s*audit_context\\b[^>]*>`.
  - Wrapped `compactPreviousSteps` with `sanitizeUntrustedContent(...)`.
  - Enriched `formatStepResultJson` to serialize a combined payload containing both `parsedData` and `observations`.
  - Added regression tests in `LlmContextBudgeterTest` verifying attribute neutralization, prior step sanitization, and observation inclusion.

---

### P12-03 [MEDIUM] [CORRECTNESS & RACE CONDITION]: Missing State/Status Guards on Commentary Endpoint and Un-fenced Late Advisory Outputs
- **Issue:**
  - `LlmAdvisoryController.requestStepComment` and `LlmAdvisoryTxService.validateStepAccess` verified session existence and ownership, but did not verify that the session was `ACTIVE` or that the step was `COMPLETED`. Clients could trigger commentary on aborted sessions or while steps were still `RUNNING`.
  - If a session transitioned to `ABORTED` while a background Ollama HTTP inference was in flight, `recordCommentAndBroadcast` and `recordChatReplyAndBroadcast` persisted `LLM_COMMENT` audit events and published SSE messages to the aborted session.
- **Impact:** Stale advisory artifacts recorded against terminated sessions and invalid inference requests enqueued for uncompleted steps.
- **Remediation:**
  - In `LlmAdvisoryTxService.java`:
    - Updated `validateStepAccess` and `loadStepContextAndRecordQuery` to reject requests when `session.getState() != SessionState.ACTIVE` or `execution.getStatus() != ExecutionStatus.COMPLETED` with `409 Conflict`.
    - Added fencing checks in `recordCommentAndBroadcast` and `recordChatReplyAndBroadcast` that log a warning and return early if `session.getState() != SessionState.ACTIVE`.
  - Added integration regression tests in `LlmAdvisoryControllerIT` asserting 409 responses and output fencing on aborted sessions.

---

### P12-04 [LOW] [PERFORMANCE]: N+1 Observation Queries in `LlmAdvisoryTxService`
- **Issue:**
  - In `loadStepContextAndRecordQuery` and `loadChatContextAndRecordQuery`, `LlmAdvisoryTxService` looped through all completed executions and issued individual queries to `observationRepository.findByExecutionIdOrderByDetectedAtAsc(exec.getId())`, causing $N+1$ database round-trips.
- **Impact:** Sub-optimal database latency on sessions with dozens of completed steps.
- **Remediation:**
  - In `ObservationRepository.java`, updated `findBySessionIdOrderByDetectedAtAsc` with `JOIN FETCH`:
    `SELECT o FROM Observation o JOIN FETCH o.result r JOIN FETCH r.execution e WHERE e.session.id = :sessionId ORDER BY o.detectedAt ASC`.
  - In `LlmAdvisoryTxService.java`, replaced per-step queries with a single query, grouping observations by execution ID into a `Map<UUID, List<String>>` in memory.

---

### P12-05 [LOW] [UI/UX]: Orphaned Loading Spinners on Session Termination and SSE Connection Drops
- **Issue:**
  - In `useWorkspaceStore`, if an audit session was completed or aborted while a commentary request or chat message was pending, or if the SSE stream entered an error state, `requestingComment` and `sendingChat` remained `true`.
- **Impact:** Infinite loading spinners in the Right Panel AI Advisor UI.
- **Remediation:**
  - In `frontend/src/stores/workspace.ts`, updated `session_completed`, `session_aborted`, and `es.onerror` handlers to reset `requestingComment.value = false` and `sendingChat.value = false`.
  - Added unit regression test in `workspace.store.spec.ts` asserting spinner state resets across all three termination paths.

---

## Verification Summary

- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm test:run`):
  - `SessionWorkspaceView.spec.ts`: 23/23 passed.
  - `workspace.store.spec.ts`: 11/11 passed (including P12-05 spinner reset test).
  - All 9 existing frontend suites passing.
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Backend Test Suite (Unit & Integration):** 293/293 passed across all test suites (`mvnw.cmd test`):
  - `LlmAdvisoryControllerIT`: 9/9 passed (including P12-03 state/status guards and aborted session fencing).
  - `LlmContextBudgeterTest`: 9/9 passed (including P12-01 fixed-point elimination and P12-02 sanitization).
  - `LlmResponseParserTest`: 6/6 passed.
  - `OllamaHttpClientTest`: 5/5 passed.
  - All 264 existing backend tests passing.
  - Code coverage: JaCoCo instruction coverage measured at **83.5%** (12,674 of 15,179 instructions covered, meeting the $\ge 80\%$ project gate).
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-12-snapshot.md`.
