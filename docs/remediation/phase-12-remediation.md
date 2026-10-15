# Phase 12: Local LLM Advisory Integration — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-12-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-12-snapshot.md`  

---

## Remediation Checklist

- [x] **P12-01 [HIGH] [VERIFIED BUG]**: Eliminate fixed-point infinite loops in token truncation fallback within `LlmContextBudgeter.java` by tracking the immutable base payload (`baseResultJson` / `baseObsSummary`), decrementing un-suffixed length strictly monotonically via `rawLen = Math.max(30, Math.min(rawLen - 15, (int)(rawLen * 0.80)))`, adding explicit loop termination at `rawLen == 30`, and asserting non-blocking termination via unit regression test `testDeterministicTerminationWithoutInfiniteLoopOnExtremeBudget`.
- [x] **P12-02 [MEDIUM] [SECURITY VULNERABILITY]**: Harden delimiter tag sanitization in `LlmContextBudgeter.java` using whitespace- and attribute-tolerant regexes (`(?i)<\\s*/\\s*untrusted_tool_output\\b[^>]*>`, `(?i)<\\s*/\\s*audit_context\\b[^>]*>`), sanitize `compactPreviousSteps` in `buildCommentPrompts`, enrich `formatStepResultJson` to bundle heuristic observations alongside `parsedData`, and add regression tests in `LlmContextBudgeterTest`.
- [x] **P12-03 [MEDIUM] [CORRECTNESS & RACE CONDITION]**: Enforce session state and step status guards in `LlmAdvisoryTxService.java` (`validateStepAccess` and `loadStepContextAndRecordQuery` reject non-`ACTIVE` sessions and non-`COMPLETED` steps with `409 Conflict`), fence and discard late LLM advisory outputs in `recordCommentAndBroadcast` and `recordChatReplyAndBroadcast` if session state is not `ACTIVE`, and add integration regression tests in `LlmAdvisoryControllerIT`.
- [x] **P12-04 [LOW] [PERFORMANCE]**: Eliminate N+1 observation queries in `LlmAdvisoryTxService.java` by updating `ObservationRepository.findBySessionIdOrderByDetectedAtAsc` with `JOIN FETCH o.result r JOIN FETCH r.execution e`, querying once per advisory cycle, and grouping observations into an in-memory `Map<UUID, List<String>>`.
- [x] **P12-05 [LOW] [UI/UX]**: Reset `requestingComment` and `sendingChat` loading spinners to `false` in `frontend/src/stores/workspace.ts` inside `session_completed`, `session_aborted`, and `es.onerror` event handlers, and add unit regression test in `workspace.store.spec.ts`.

---

## Verification Summary

- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm test:run`):
  - `SessionWorkspaceView.spec.ts`: 23/23 passed (commentary card, on-demand re-analyze button, suggested tool execution, tactical chat submission, and strict HTML escaping / XSS protection).
  - `workspace.store.spec.ts`: 11/11 passed (including P12-05 spinner reset test on completion, abort, and error).
  - `http.spec.ts`: 16/16 passed.
  - `sessions.store.spec.ts`: 15/15 passed.
  - `NewSessionModal.spec.ts`: 11/11 passed.
  - `HomeView.spec.ts`: 8/8 passed.
  - `LoginView.spec.ts`: 9/9 passed.
  - `auth.store.spec.ts`: 11/11 passed.
  - `AppHeader.spec.ts`: 4/4 passed.
  - `health.store.spec.ts`: 4/4 passed.
  - `router.spec.ts`: 4/4 passed.
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Backend Test Suite (Unit & Integration):** 293/293 passed across all test suites (`mvnw.cmd test`):
  - `LlmAdvisoryControllerIT`: 9/9 passed (202 Accepted, 404 BOLA cross-session protection, 409 step status/session state conflicts, AuditEvent persistence, SSE broadcasts, and late output fencing).
  - `LlmContextBudgeterTest`: 9/9 passed (1,450-token ceiling, single/multi-step summarization, delimiter neutralization with attributes, observations inclusion, and deterministic loop termination).
  - `LlmResponseParserTest`: 6/6 passed (JSON comment parsing, hallucinated tool allowlist sanitization, markdown fence removal, and raw text fallback).
  - `OllamaHttpClientTest`: 5/5 passed (WireMock request payload format and connection error translation).
  - All 264 existing backend test suites passing.
  - Code coverage: JaCoCo instruction coverage measured at **83.5%** (12,674 of 15,179 instructions covered, meeting the $\ge 80\%$ project gate).
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-12-snapshot.md`.
