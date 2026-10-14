# Phase 3: Backend Foundation — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-03-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-03-snapshot.md`  

---

## Remediation Checklist

- [x] **P3-01 [HIGH] [VERIFIED BUG]**: Add `HttpMessageNotReadableException` and `MethodArgumentTypeMismatchException` handlers to `GlobalExceptionHandler` (`400 Bad Request` per RFC 9457) and unit tests in `GlobalExceptionHandlerTest`.
- [x] **P3-02 [HIGH] [VERIFIED BUG]**: Isolate Windows-specific `DOCKER_HOST` named pipe inside a dedicated Maven profile `windows-docker` in `backend/pom.xml`.
- [x] **P3-03 [MEDIUM] [VERIFIED BUG]**: Switch password hashing in `SecurityConfig` to `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`.
- [x] **P3-04 [MEDIUM] [UNPROVEN GUARANTEE]**: Pre-create `ospysin_app` role in `AbstractIntegrationTest` before Flyway runs and remove manual `GRANT/REVOKE` from `DatabaseImmutabilityAndPrivilegesIT`.
- [x] **P3-05 [MEDIUM] [VERIFIED BUG]**: Enforce explicit `@Builder` constructors without `id` across all 11 JPA entities, apply `@Immutable` without setters on append-only entities, and retain setters strictly on mutable fields of mutable entities.
- [x] **P3-06 [LOW] [VERIFIED BUG]**: Create `enum AuditEventType` (11 canonical values), type `AuditEvent.eventType` with `@Enumerated(EnumType.STRING)`, add `CHECK` constraint in `V1__init_schema.sql`, and align tests.
- [x] **P3-07 [LOW] [VERIFIED BUG]**: Normalize `ollamaBaseUrl` in `HealthController`, add negative test in `HealthControllerIT`, and add `check` goal to `jacoco-maven-plugin`.
- [x] **P3-08 [LOW] [VERIFIED BUG]**: Fix failed test regex in `scripts/bundle-phase.ps1` to prevent false-positive reporting on passing suites.

---

## Verification Summary
- **Tests Executed:** 23/23 tests passed (`mvnw.cmd test` / `mvnw.cmd clean verify`).
  - `DatabaseImmutabilityAndPrivilegesIT`: 4/4 passed (role privilege separation verified via Flyway V1 migration).
  - `FlywaySchemaAndEntitiesIT`: 3/3 passed (full entity chain + `AuditEventType.FINDING_CREATED`).
  - `GlobalExceptionHandlerTest`: 7/7 passed (including malformed JSON and parameter type mismatch returning 400 Bad Request).
  - `HealthControllerIT`: 2/2 passed (including advisory Ollama DOWN when unreachable returning 200 OK).
  - `Utf8ByteTruncationTest`: 7/7 passed (UTF-8 multi-byte boundary and 1 MB limit verification).
- **Snapshot Generated:** `docs/audits/snapshots/phase-03-snapshot.md` with 0 false-positive failed test reports.
- **Git Commit:** Not executed (per Quality Gates & Git Discipline).
