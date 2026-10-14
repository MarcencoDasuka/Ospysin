# Phase 8: Session List & New Session Setup Modal UI — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-08-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-08-snapshot.md`  

---

## Remediation Checklist

- [x] **P8-01 [HIGH] [VERIFIED BUG]**: Prevent swallowed `409 Conflict` errors by adding an action error banner (`data-testid="workspace-action-error"`) inside `<main v-else-if="currentSession">` with dismiss button in `SessionWorkspaceView.vue`, reset `currentSession.value = null` in `fetchSessionById()`, add route parameter `watch(sessionId)` for dynamic workspace route changes, and guard `HomeView.vue` list error banner with `!isNewModalOpen`.
- [x] **P8-02 [MEDIUM] [VERIFIED BUG]**: Wrap `await sessionsStore.fetchSessions(...)` inside `try / catch` blocks in `HomeView.vue` pagination handlers (`handlePrevPage()` and `handleNextPage()`) to prevent unhandled promise rejections on network/API failure.
- [x] **P8-03 [LOW] [VERIFIED BUG]**: Replace non-focusable backdrop `@keydown.esc` with a global `window` `'keydown'` listener in `NewSessionModal.vue` with immediate attachment on `visible: true` and deterministic removal on modal close and component `onUnmounted`.
- [x] **P8-04 [LOW] [VERIFIED BUG]**: Enforce pagination page bounds in `sessions.ts` by slicing prepended `sessions.value` to `size.value` and recalculating `totalPages.value = Math.max(1, Math.ceil(totalElements.value / size.value))` upon successful `createSession()`.

---

## Verification Summary

- **Frontend Tests Executed:** 89/89 passed across 10 test files (`pnpm test:coverage` / `pnpm test:run`).
  - `sessions.store.spec.ts`: 15/15 passed (lifecycle methods, RFC 9457 error handling, concurrency lock, stale session clearing on fetch, pagination slicing and totalPages recalculation).
  - `NewSessionModal.spec.ts`: 11/11 passed (default mode PUBLIC, submit button disabled gate, payload formatting, 403 PolicyEngine rejection display, in-flight lock, Escape key window event handling, unmount listener cleanup).
  - `HomeView.spec.ts`: 8/8 passed (table rendering, badges, empty state, modal integration, route navigation, pagination controls, error banner bleed prevention, pagination try/catch safety).
  - `SessionWorkspaceView.spec.ts`: 7/7 passed (session context bar, complete and abort actions, 409 Conflict action banner and dismissal, 404 route transition clearing currentSession, back navigation).
  - Pre-existing frontend test suites: `http.spec.ts` (16/16), `auth.store.spec.ts` (11/11), `LoginView.spec.ts` (9/9), `AppHeader.spec.ts` (4/4), `health.store.spec.ts` (4/4), `router.spec.ts` (4/4).
- **Frontend Code Coverage:** 96.74% statement coverage, 81.32% branch coverage, 92.68% function coverage, 96.74% line coverage (all exceeding the 60% requirement).
- **TypeScript & Production Build:** `vue-tsc --noEmit && vite build` completed cleanly in 1.66s with zero errors.
- **Backend Tests Executed:** 204/204 passed (`mvnw.cmd test`).
  - `AuditSessionControllerIT`: 9/9 passed
  - `AuditSessionServiceTest`: 4/4 passed
  - `ScopeAttestationRegistryTest`: 6/6 passed
  - Pre-existing regression suites: 185/185 passed.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-08-snapshot.md`.
