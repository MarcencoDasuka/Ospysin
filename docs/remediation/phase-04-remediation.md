# Phase 4: Operator Session Authentication & CSRF Security — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-04-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-04-snapshot.md`  

---

## Remediation Checklist

- [x] **P4-01 [MEDIUM] [VERIFIED BUG]**: Override `shouldNotFilter` in `CsrfCookieFilter` for `POST /api/auth/login`, remove redundant `csrfTokenRepository.saveToken(null)` from `AuthService.logout()`, and add AssertJ assertions in `AuthControllerIT` verifying exactly 1 `XSRF-TOKEN` and 1 `JSESSIONID` cookie in `Set-Cookie`.
- [x] **P4-02 [LOW] [VERIFIED BUG]**: Remove `@Transactional(readOnly = true)` from `AuthService.login()` to eliminate HikariCP database connection retention during CPU/memory-intensive Argon2id password hashing and session rotation.
- [x] **P4-03 [MEDIUM] [VERIFIED BUG]**: Configure `mock-maker-subclass` in `backend/src/test/resources/mockito-extensions/org.mockito.plugins.MockMaker`, add `-XX:+EnableDynamicAgentLoading` to Surefire, and configure quoted relative `target/jacoco.exec` paths in `backend/pom.xml` for resilient Windows non-ASCII execution under Java 21.

---

## Verification Summary
- **Tests Executed:** 30/30 tests passed (`mvnw.cmd test` / `mvnw.cmd clean verify`).
  - `AuthControllerIT`: 7/7 passed (session fixation defense, Argon2id auth, 401/422 RFC 9457 error details, CSRF enforcement, single-cookie verification).
  - `DatabaseImmutabilityAndPrivilegesIT`: 4/4 passed (role privilege separation verified via Flyway V1 migration).
  - `FlywaySchemaAndEntitiesIT`: 3/3 passed (full entity chain + `AuditEventType.FINDING_CREATED`).
  - `GlobalExceptionHandlerTest`: 7/7 passed (RFC 9457 Problem Details formatting, malformed JSON, parameter mismatch, internal error sanitization).
  - `HealthControllerIT`: 2/2 passed (including advisory Ollama DOWN when unreachable returning 200 OK).
  - `Utf8ByteTruncationTest`: 7/7 passed (UTF-8 multi-byte boundary and 1 MB limit verification).
- **Coverage Analysis:** JaCoCo >= 80% line coverage verified (`jacoco:check` passed).
- **Snapshot Generated:** `docs/audits/snapshots/phase-04-snapshot.md` verified clean with 0 test failures.
