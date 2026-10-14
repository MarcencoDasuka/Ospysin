# Phase 5: Frontend Foundation, Typed RFC 9457 API Client & Login View — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-05-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-05-snapshot.md`  

---

## Remediation Checklist

- [x] **P5-01 [HIGH] [VERIFIED BUG]**: Treat cold-start 401 in `authStore.fetchCurrentUser()` as normal guest state (`error.value = null`), call `clearError()` on `LoginView` mount, honor safe internal `redirect` query parameters, and prevent open redirects (`//evil.example`).
- [x] **P5-02 [LOW] [VERIFIED BUG]**: Escape regex metacharacters in `getCookie()` and wrap `decodeURIComponent` in exception handling to prevent runtime crashes from malformed cookie values in `http.ts`.
- [x] **P5-03 [LOW] [VERIFIED INCONSISTENCY]**: Align copy in `HomeView.vue` from `"passive reconnaissance"` to `"non-destructive reconnaissance"`.
- [x] **P5-04 [LOW] [VERIFIED BUG]**: Set `$env:NO_COLOR = "1"`, invoke `pnpm.cmd` on Windows, and filter ANSI escape codes and PowerShell error noise from frontend test execution logs in `scripts/bundle-phase.ps1`.

---

## Verification Summary
- **Tests Executed:** 48/48 frontend tests passed (`pnpm.cmd test --run`).
  - `http.spec.ts`: 16/16 passed (RFC 9457 parsing, `invalidParams`, cookie regex escaping, `URIError` fallback, CSRF header propagation, 401 callback).
  - `auth.store.spec.ts`: 11/11 passed (login, logout, fetchCurrentUser normal guest 401 vs 500 error state, clearError).
  - `health.store.spec.ts`: 4/4 passed (system/database/Ollama health, status badges, failure fallback).
  - `LoginView.spec.ts`: 9/9 passed (form rendering, double-submit guard, RFC 9457 error callout, invalidParams list, mount clearError, safe internal redirect, open redirect rejection).
  - `AppHeader.spec.ts`: 4/4 passed (branding, operator username, Ollama READY/OFFLINE badge, logout trigger).
  - `router.spec.ts`: 4/4 passed (cold-start auth check, unauthenticated redirect to `/login`, authenticated route protection).
- **Backend Tests Executed:** 30/30 backend tests passed (`./mvnw.cmd test`).
- **Frontend Coverage:** **96.94% Line Coverage** achieved (exceeding the >= 60% requirement).
- **TypeScript Compilation:** `vue-tsc --noEmit && vite build` succeeded with zero type errors.
- **Audit Snapshot:** Regenerated clean snapshot via `bundle-phase.ps1` with zero ANSI artifacts.
