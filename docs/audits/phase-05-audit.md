# Phase 5: Frontend Foundation, Typed RFC 9457 API Client & Login View — Architectural & Security Audit Report

**Date:** 2026-10-14  
**Audit Target:** `phase-05-snapshot.md` (Vue 3, TypeScript 5, Vite 5, Axios RFC 9457 client, CSRF header propagation, Pinia `useAuthStore` and `useHealthStore`, Screen 0 `LoginView.vue`, Screen 1 shell `AppHeader.vue` / `HomeView.vue`, Vitest component suite)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary
An architectural, security, and component audit of the Phase 5 implementation identified 4 findings (1 High, 3 Low) spanning cold-start authentication error banner leakage, open redirect vulnerabilities, cookie parser regex escaping and URI decoding safety, specification terminology alignment, and ANSI formatting in verification scripts. All 4 findings have been verified, remediated, and covered by automated unit and component tests.

---

## Detailed Findings & Remediations

### P5-01 [HIGH] [VERIFIED BUG]: False-Positive 401 Error Banner on Initial Visit to `/login` and Ignored `redirect` Query Parameter
- **Issue:**
  1. On cold start (`status === 'idle'`), `router.beforeEach` in `frontend/src/router/index.ts` calls `authStore.fetchCurrentUser()`. For an unauthenticated visitor, `GET /api/auth/me` returns `401 Unauthorized`. Previously, `fetchCurrentUser()` recorded this 401 response into `authStore.error`. When the router subsequently redirected the visitor to `/login`, `LoginView.vue` immediately displayed the red `error-callout` alert box ("Authentication Error: Unable to retrieve authenticated operator session") before the user had entered any credentials or attempted to sign in.
  2. In `LoginView.vue`, upon successful authentication, the component executed a hardcoded `router.push('/')` and ignored the `redirect` query parameter passed by the router navigation guard (`/login?redirect=...`). Furthermore, an unvalidated `redirect` query could expose the application to open redirect vulnerabilities if not sanitized against scheme-relative URLs (`//evil.example`).
- **Impact:** Degraded user experience (false failure alert upon visiting the login page) and loss of intended operator destination upon session re-authentication.
- **Remediation:**
  - Updated `fetchCurrentUser()` in `frontend/src/stores/auth.ts` to treat a `401` response as normal guest state (`error.value = null`, `user.value = null`, `status.value = 'unauthenticated'`), setting `error` only on unexpected non-401 failures (e.g., 500 server errors).
  - Added an `onMounted` lifecycle hook in `frontend/src/views/LoginView.vue` calling `authStore.clearError()` to ensure stale authentication errors are flushed upon viewing the login form.
  - Updated `LoginView.vue` to inspect `route.query.redirect`: if it is a safe relative path (`redirect.startsWith('/') && !redirect.startsWith('//')`), the router navigates to that path; otherwise, it safely defaults to `'/'`.
  - Added unit and component tests in `auth.store.spec.ts` and `LoginView.spec.ts` covering cold-start 401 null-error state, `clearError()` on mount, safe internal redirection, and rejection of open redirect targets.

---

### P5-02 [LOW] [VERIFIED BUG]: Regex Metacharacter Escaping and `URIError` Safety in `getCookie()` (`frontend/src/api/http.ts`)
- **Issue:** `getCookie(name)` in `frontend/src/api/http.ts` concatenated the cookie `name` directly into `new RegExp('(?:^|;\\s*)' + name + '=([^;]*)')`. If a cookie name contained regex metacharacters (e.g. `[`, `]`, `.`, `*`), `RegExp` compilation threw syntax errors. Additionally, `decodeURIComponent(match[1])` was invoked without exception handling; malformed cookie values with invalid percent-encoding threw uncaught `URIError` exceptions, interrupting the Axios request interceptor.
- **Impact:** Potential client runtime crash in the request interceptor when parsing unusual or malformed browser cookies.
- **Remediation:**
  - Added regex metacharacter escaping: `const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')`.
  - Wrapped `decodeURIComponent` in a `try ... catch` block that safely falls back to returning the raw cookie string if decoding fails.
  - Added unit test cases in `frontend/src/__tests__/http.spec.ts` verifying metacharacter handling and malformed URI decoding resilience.

---

### P5-03 [LOW] [VERIFIED INCONSISTENCY]: Legacy "Passive Reconnaissance" Wording in `frontend/src/views/HomeView.vue`
- **Issue:** Line 54 of `frontend/src/views/HomeView.vue` referenced `"passive reconnaissance"` in the empty state description, conflicting with the authoritative project vocabulary in `docs/15-GLOSSARY.md` and `docs/01-SCOPE.md` which designates Tier 2 actions as "non-destructive reconnaissance".
- **Impact:** Minor terminology inconsistency between frontend UI copy and domain specifications.
- **Remediation:** Replaced `"passive reconnaissance"` with `"non-destructive reconnaissance"` in `frontend/src/views/HomeView.vue`.

---

### P5-04 [LOW] [VERIFIED BUG]: ANSI Color Escape Sequences and `NativeCommandError` in `scripts/bundle-phase.ps1` Frontend Logs
- **Issue:** When `pnpm test --run` ran inside `scripts/bundle-phase.ps1`, Vitest emitted ANSI color escape codes (`\x1B[...]`) into stdout, cluttering markdown audit snapshots. In addition, capturing native stderr into PowerShell (`2>&1`) produced `NativeCommandError` / `FullyQualifiedErrorId` noise on standard Windows configurations.
- **Impact:** Cluttered snapshot logs with unparsed ANSI terminal codes and spurious PowerShell wrapper warnings.
- **Remediation:**
  - Set `$env:NO_COLOR = "1"` during the frontend verification block in `scripts/bundle-phase.ps1`.
  - Prefer `pnpm.cmd` explicitly on Windows host systems before falling back to `pnpm`.
  - Stripped ANSI escape codes (`-replace '\x1B\[[0-9;]*[a-zA-Z]', ''`) and filtered out `NativeCommandError`, `CategoryInfo`, and `FullyQualifiedErrorId` lines.
