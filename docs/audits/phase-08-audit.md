# Phase 8: Session List & New Session Setup Modal UI — Architectural & Frontend Audit Report

**Date:** 2026-10-14  
**Audit Target:** `phase-08-snapshot.md` (Frontend session management, Pinia session store, Screen 1 session list table, Screen 2 modal with scope attestation gate, Screen 3 workspace shell)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An architectural, frontend reactivity, and error-boundary audit of the Phase 8 implementation identified 4 findings (1 High, 1 Medium, 2 Low) spanning unrendered `409 Conflict` action failures in `SessionWorkspaceView.vue`, stale session caching masking `404 Not Found` errors in `fetchSessionById()`, list error banner leakage during modal interaction, unhandled promise rejections in pagination controls, non-deterministic `Escape` key event handling in `NewSessionModal.vue`, and pagination bounding on session creation. All 4 findings have been verified, remediated, and covered with automated Vitest tests.

---

## Detailed Findings & Remediations

### P8-01 [HIGH] [VERIFIED BUG]: Swallowed 409 Conflict Errors, Stale Session Retention on 404, and Shared Error Banner Bleed
- **Issue:**
  1. In `SessionWorkspaceView.vue`, error feedback was restricted to `v-else-if="error && !currentSession"`. When a session was already loaded and an action (`completeSession` or `abortSession`) failed with `409 Conflict` (e.g., active background tool tasks running), `sessionsStore.error` was populated, but no error UI was rendered inside `<main v-else-if="currentSession">`, making the failure invisible to the operator.
  2. In `frontend/src/stores/sessions.ts`, `fetchSessionById(id)` did not reset `currentSession.value = null` before dispatching the GET request. Navigating from an active session to a non-existent session ID (`404`) retained the previous session in memory, preventing `v-else-if="error && !currentSession"` from rendering the 404 error card. Furthermore, `SessionWorkspaceView.vue` only loaded sessions on `onMounted` and did not watch route parameter changes.
  3. In `HomeView.vue`, `v-if="error"` rendered `data-testid="sessions-list-error"` globally, leaking error state onto the main list view even when `NewSessionModal` was open and displaying its own contextual error callout.
- **Impact:** Operator actions that fail due to backend conflicts fail silently without visual feedback. Stale session state can be displayed under non-existent route IDs. Shared store error state pollutes parent views while child modals handle contextual errors.
- **Remediation:**
  - In `frontend/src/stores/sessions.ts`, added `currentSession.value = null` prior to the GET request in `fetchSessionById(id: string)`.
  - In `frontend/src/views/SessionWorkspaceView.vue`, added an action error banner (`v-if="error"`, `data-testid="workspace-action-error"`) inside `<main v-else-if="currentSession">` with RFC 9457 title, detail, and a dismiss button calling `sessionsStore.clearError()`.
  - In `SessionWorkspaceView.vue`, added `watch(sessionId, async (newId) => { ... })` to automatically reload target sessions when route parameters change.
  - In `frontend/src/views/HomeView.vue`, updated the list error banner condition to `v-if="error && !isNewModalOpen"`.
  - Added tests in `SessionWorkspaceView.spec.ts` verifying that `409 Conflict` displays `data-testid="workspace-action-error"` while keeping the workspace visible, and navigating to a `404` route resets `currentSession` and displays `data-testid="workspace-error-card"`. Added a test in `HomeView.spec.ts` verifying error banner suppression while the modal is open.

---

### P8-02 [MEDIUM] [VERIFIED BUG]: Unhandled Promise Rejections in HomeView Pagination Handlers
- **Issue:** `sessionsStore.fetchSessions()` rethrows `ApiError` to allow callers to inspect or handle network failures. Unlike `onMounted()`, `handlePrevPage()` and `handleNextPage()` in `HomeView.vue` invoked `await sessionsStore.fetchSessions(...)` without `try / catch` blocks.
- **Impact:** Network drops or API errors during pagination triggered unhandled promise rejections in the browser runtime.
- **Remediation:**
  - Wrapped `await sessionsStore.fetchSessions(...)` inside `try { ... } catch { /* captured in store.error */ }` in both `handlePrevPage()` and `handleNextPage()`.
  - Added test in `HomeView.spec.ts` asserting pagination failures are gracefully caught without unhandled rejections.

---

### P8-03 [LOW] [VERIFIED BUG]: Non-Deterministic Escape Key Listener in NewSessionModal
- **Issue:** The modal relied on `@keydown.esc="closeModal"` on the outer backdrop `<div>`. If the operator clicked inside the dialog where focus was not held by a native interactive element listening to keyup/keydown bubbles, the Escape key would not close the modal.
- **Impact:** Inconsistent keyboard navigation and accessibility behavior.
- **Remediation:**
  - Added a global `window` `'keydown'` listener for `'Escape'` inside `watch(() => props.visible, ..., { immediate: true })`.
  - Ensured deterministic cleanup on modal close and inside `onUnmounted` per the `vue-frontend` skill guidelines.
  - Added tests in `NewSessionModal.spec.ts` verifying window Escape keydown emits `update:visible(false)`, respects `creating` lock, and removes the listener on unmount.

---

### P8-04 [LOW] [VERIFIED BUG]: Unbounded Session Array and Stale totalPages on createSession()
- **Issue:** In `frontend/src/stores/sessions.ts`, `createSession()` prepended the created session into `sessions.value` without slicing to the active page `size.value` or updating `totalPages.value`.
- **Impact:** If the first page already contained `size` (e.g. 20) elements, creating a session caused the list to expand to 21 elements without incrementing `totalPages` or preserving pagination consistency.
- **Remediation:**
  - Bounded `sessions.value` with `.slice(0, size.value)`.
  - Recalculated `totalPages.value = Math.max(1, Math.ceil(totalElements.value / size.value))`.
  - Added a test in `sessions.store.spec.ts` asserting list slicing and `totalPages` recalculation.
