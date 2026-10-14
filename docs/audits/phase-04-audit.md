# Phase 4: Operator Session Authentication & CSRF Security — Architectural & Security Audit Report

**Date:** 2026-10-14  
**Audit Target:** `phase-04-snapshot.md` (Stateful session cookie authentication, CSRF token protection, SPA request handler, AuthController, AuthService, AuthControllerIT)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary
An architectural, concurrency, and security audit of the Phase 4 implementation identified 3 findings (2 Medium, 1 Low) spanning duplicate cookie headers on authentication boundaries, connection pool retention during CPU-intensive password hashing, and cross-platform build/agent compatibility on Windows with non-ASCII user home paths under Java 21. All 3 findings have been verified, remediated, and covered by automated tests.

---

## Detailed Findings & Remediations

### P4-01 [MEDIUM] [VERIFIED BUG]: Duplicate `Set-Cookie: XSRF-TOKEN` Headers on `/api/auth/login` and `/api/auth/logout`
- **Issue:**
  1. On `POST /api/auth/login`, `CsrfCookieFilter` executed before the controller and invoked `csrfToken.getToken()`, writing an initial `Set-Cookie: XSRF-TOKEN` header to the response. Subsequently, `AuthService.login()` explicitly invoked `csrfTokenRepository.generateToken()` and `saveToken()`, appending a second `Set-Cookie: XSRF-TOKEN` header with a different token value to the same response.
  2. On `POST /api/auth/logout`, `AuthService.logout()` called `csrfTokenRepository.saveToken(null, httpRequest, httpResponse)` (which added an expiring `XSRF-TOKEN` cookie) and then manually constructed and added an explicit `clearXsrfCookie`, resulting in two duplicate `Set-Cookie: XSRF-TOKEN` expiration headers on logout.
- **Impact:** Redundant and potentially conflicting cookie instructions delivered to browsers and HTTP clients, leading to non-deterministic CSRF token evaluation in Single-Page Applications.
- **Remediation:**
  - Overrode `shouldNotFilter(HttpServletRequest request)` in `SecurityConfig.CsrfCookieFilter` to skip execution for `POST /api/auth/login` (`"POST".equalsIgnoreCase(request.getMethod()) && ("/api/auth/login".equals(request.getServletPath()) || request.getRequestURI().endsWith("/api/auth/login"))`), ensuring only the post-authentication fresh token from `AuthService.login()` is written.
  - Removed the redundant `csrfTokenRepository.saveToken(null, ...)` call from `AuthService.logout()`, letting the explicit hardened `clearXsrfCookie` (`Path=/`, `Max-Age=0`, `SameSite=Strict`, `Secure`) clear the cookie once.
  - Added assertions in `AuthControllerIT` verifying that `login` and `logout` responses contain exactly 1 `XSRF-TOKEN` and 1 `JSESSIONID` header in `response.getHeaders("Set-Cookie")`.

---

### P4-02 [LOW] [VERIFIED BUG]: Connection Pool Retention Across Argon2id Hashing in `AuthService.login()`
- **Issue:** `AuthService.login()` was annotated with `@Transactional(readOnly = true)`. Because Spring checks out an active JDBC connection from the HikariCP pool for the entire method execution, the connection was held while `authenticationManager.authenticate()` executed memory-hard and CPU-intensive Argon2id password hashing and while HTTP session rotation/cookie operations executed.
- **Impact:** Violation of `spring-backend` concurrency rules ("Keep transaction scope narrow to prevent HikariCP connection pool starvation"). Under concurrent login load, pooled connections were unnecessarily blocked during hashing.
- **Remediation:** Removed `@Transactional` from `AuthService.login()`. The `UserRepository.findByUsername()` query executes within its own short-lived repository transaction after credential verification completes.

---

### P4-03 [MEDIUM] [VERIFIED BUG]: Surefire, JaCoCo, and Mockito Agent Initialization Failures on Windows Non-ASCII Paths under Java 21
- **Issue:**
  1. Under Java 21, Mockito 5.x default inline mock maker failed to dynamically self-attach via ByteBuddy due to Java 21 dynamic agent loading restrictions and path decoding errors on Windows environments with Cyrillic or space-containing user paths (`C:\Users\наш компухтер\...`).
  2. Maven Surefire forked JVM command line failed when `-javaagent` paths containing spaces were not explicitly quoted in `pom.xml`, causing `cmd.exe` to split arguments and crash the forked JVM.
  3. JaCoCo's default absolute path resolution for `destfile` failed when passed through JVM argument lists containing Cyrillic characters.
- **Impact:** Build and test failures during `mvnw clean verify` and inability to generate the `jacoco.exec` coverage data file.
- **Remediation:**
  - Added `mock-maker-subclass` configuration in `backend/src/test/resources/mockito-extensions/org.mockito.plugins.MockMaker` to enable deterministic subclass mocking without requiring dynamic agent attachment.
  - Added `-XX:+EnableDynamicAgentLoading` to `maven-surefire-plugin` configuration in `backend/pom.xml`.
  - Configured XML-quoted `&quot;-javaagent:...=destfile=target/jacoco.exec&quot;` in `backend/pom.xml` with relative `target/jacoco.exec` data paths, ensuring resilient cross-platform execution on Windows with non-ASCII usernames.
