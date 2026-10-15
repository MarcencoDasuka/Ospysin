# Phase 11: Session Workspace UI (4-Panel Layout, Inspector & Live SSE Stream) — Architectural & Security Audit Report

**Date:** 2026-10-15  
**Audit Target:** `phase-11-snapshot.md` (Session Workspace UI: 4-Panel Layout, Tool Execution Inspector, Live SSE Event Log, and Pinia Workspace Store)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An adversarial audit of the Phase 11 implementation identified 4 findings (2 Medium, 2 Low) spanning structured redirect hop payload rendering in `SessionWorkspaceView.vue`, center inspector state desynchronization when new tools are queued in `useWorkspaceStore`, post-unmount or route-switch SSE connection leaks in `loadWorkspaceData`, and missing asynchronous awaiting of step selection in `fetchSteps`. All 4 findings have been remediated, verified, and validated across 107 frontend Vitest tests and 264 backend Maven tests (spanning unit and Testcontainers PostgreSQL integration suites), with clean production build bundling (`vue-tsc --noEmit && vite build`).

---

## Detailed Findings & Remediations

### P11-01 [MEDIUM] [VERIFIED BUG]: Object-to-String Cast in `parsedRedirectChain` for Structured Redirect Entries
- **Issue:**
  - `PinnedHttpClient.java` records redirect hops in `redirectChain` as structured maps: `{ hop: number, fromUrl: string, toUrl: string, statusCode: number }`.
  - In `SessionWorkspaceView.vue`, `parsedRedirectChain` previously performed a direct cast `chain as string[]`, causing structured redirect objects to display as uninformative `[object Object]` entries in the Response Inspector.
  - `frontend/src/api/types.ts` lacked a typed contract for redirect hops.
- **Impact:** HTTP header probe redirect chains could not be inspected properly by the operator when targets executed multi-hop redirects.
- **Remediation:**
  - In `frontend/src/api/types.ts`, declared `RedirectHopView` (`{ hop?: number, fromUrl?: string, toUrl?: string, statusCode?: number }`).
  - In `frontend/src/views/SessionWorkspaceView.vue`, updated `parsedRedirectChain` to normalize both structured redirect objects (`Hop ${hopNum}${status}: ${from} -> ${to}`) and legacy/fallback string entries into clean display strings.
  - Added unit regression test in `SessionWorkspaceView.spec.ts` asserting formatted display of structured redirect objects.

---

### P11-02 [MEDIUM] [VERIFIED BUG]: Center Inspector Desynchronization & Blank State Upon Queueing Tools
- **Issue:**
  - In `useWorkspaceStore`, when `runTool()` enqueued a task or when `step_queued` arrived via SSE, `activeStepId` was set to the new step's `executionId`, but `activeStepDetail` was left as `null` (if no steps existed) or remained set to an older `COMPLETED` step.
  - Consequently, the Center Panel failed to transition immediately to the pending/running state, either displaying an empty view or rendering stale results while the new probe executed.
- **Impact:** Confusing UI feedback and stale evidence rendering during tool execution.
- **Remediation:**
  - In `frontend/src/stores/workspace.ts`:
    - Updated `runTool()` to immediately assign a `PENDING` `StepDetailResponse` snapshot to `activeStepDetail.value` alongside `activeStepId.value = accepted.executionId`.
    - Updated the `step_queued` SSE listener to set `activeStepDetail.value` to an initial `PENDING` snapshot when `activeStepId` tracks the newly queued step.
  - In `frontend/src/views/SessionWorkspaceView.vue`:
    - Added computed `activeStepSummary` referencing the active step in the chronological `steps` timeline.
    - Updated `inspector-step-running` condition to check both `activeStepSummary` and `activeStepDetail` for `PENDING` or `RUNNING` status.
  - Added regression tests in `workspace.store.spec.ts` and `SessionWorkspaceView.spec.ts`.

---

### P11-03 [LOW] [VERIFIED BUG]: Potential Post-Unmount or Stale-Route SSE Connection Leak in `loadWorkspaceData`
- **Issue:**
  - In `SessionWorkspaceView.vue`, `loadWorkspaceData(id)` initiates multiple asynchronous operations (`fetchSessionById`, `fetchTools`, `fetchSteps`, `checkHealth`).
  - If the user navigated away from the workspace (unmounting the component) or switched sessions before these promises settled, `workspaceStore.connectSse(id)` could be invoked after unmount, leaving an orphaned `EventSource` connection streaming in the background.
- **Impact:** Memory leaks and redundant network bandwidth consumption from lingering SSE event listeners.
- **Remediation:**
  - Added an `isUnmounted` lifecycle guard (`false` on mount, `true` on unmount) in `SessionWorkspaceView.vue`.
  - Added short-circuit checks `if (isUnmounted || sessionId.value !== id) return` after `fetchSessionById` and after `Promise.allSettled(...)` before calling `connectSse(id)`.
  - Added regression test in `SessionWorkspaceView.spec.ts` verifying that `connectSse` is not called if the component is unmounted while session fetching is in flight.

---

### P11-04 [LOW] [VERIFIED BUG]: Unhandled Floating Promise on `selectStep` in `fetchSteps`
- **Issue:**
  - In `useWorkspaceStore.fetchSteps(sessionId)`, the store automatically selected the latest step if none was currently active by calling `selectStep(sessionId, latest.executionId)`.
  - However, `selectStep` is an async function that returns a `Promise`, but it was called without `await`, resulting in an unhandled floating promise and potential race conditions during initial view rendering.
- **Impact:** Potential race condition or unhandled rejection during workspace initialization.
- **Remediation:**
  - In `frontend/src/stores/workspace.ts`, updated `fetchSteps` to `await selectStep(sessionId, latest.executionId)`.
  - Verified clean asynchronous sequencing across all store and view tests.

---

## Verification Summary

- **Frontend Unit & Component Tests:** 107/107 passed across 11 test suites (`pnpm test:run`):
  - `SessionWorkspaceView.spec.ts`: 18/18 passed.
  - `workspace.store.spec.ts`: 7/7 passed.
  - All other 9 existing frontend suites passing.
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Backend Test Suite (Unit & Integration):** 264/264 passed across all test suites (`mvnw.cmd test`):
  - 100% of tests passed with 0 failures, 0 errors, and 0 skipped.
  - Code coverage: JaCoCo report generated meeting project thresholds (instruction coverage >= 80% project gate).
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-11-snapshot.md`.
