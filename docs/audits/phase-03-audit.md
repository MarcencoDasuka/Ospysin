# Phase 3: Backend Foundation — Architectural & Security Audit Report

**Date:** 2026-10-14  
**Audit Target:** `phase-03-snapshot.md` (Spring Boot 3.3.4, Java 21, Flyway, PostgreSQL 16 schema, JPA entities, Security, Test suite)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary
An architectural and security audit of the Phase 3 implementation identified 8 issues (2 High, 3 Medium, 3 Low) spanning RFC 9457 error handling, cross-platform build configuration, credential hashing algorithms, role privilege separation verification in integration tests, JPA entity encapsulation and builder hygiene, audit ledger type safety, health check URL normalization, and snapshot test report filtering. All 8 findings have been fully remediated and verified.

---

## Detailed Findings & Remediations

### P3-01 [HIGH] [VERIFIED BUG]: Missing JSON Deserialization and Parameter Type Mismatch Handling in `GlobalExceptionHandler`
- **Issue:** `backend/src/main/java/com/ospysin/shared/error/GlobalExceptionHandler.java` lacked handlers for `HttpMessageNotReadableException` (malformed JSON syntax) and `MethodArgumentTypeMismatchException` (path/query parameter type mismatch, such as malformed UUIDs). Unhandled exceptions fell back to the catch-all `Exception.class` handler, returning `500 Internal Server Error` instead of `400 Bad Request`.
- **Impact:** Violation of `docs/04-API-CONTRACTS.md` and RFC 9457; client errors were reported as internal server failures.
- **Remediation:** Added `@ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})` returning `400 Bad Request` with standard `ProblemDetail` (`type: https://ospysin.dev/errors/bad-request`, `title: Bad Request`), hiding internal class names and stack traces. Covered by unit tests in `backend/src/test/java/com/ospysin/shared/error/GlobalExceptionHandlerTest.java`.

---

### P3-02 [HIGH] [VERIFIED BUG]: Hardcoded Windows Named Pipe `DOCKER_HOST` in `backend/pom.xml`
- **Issue:** The `<build><plugins><plugin>maven-surefire-plugin` configuration contained a hardcoded system property:
  `<DOCKER_HOST>npipe:////./pipe/dockerDesktopLinuxEngine</DOCKER_HOST>`.
  When executing on Linux, macOS, or in containerized CI environments (such as GitHub Actions), Testcontainers attempted to connect to the non-existent Windows named pipe instead of the standard `/var/run/docker.sock` Unix domain socket.
- **Impact:** Test execution and Maven builds failed unconditionally on all non-Windows platforms.
- **Remediation:** Extracted `DOCKER_HOST` into a dedicated Maven profile `windows-docker`, conditionally activated via `<os><family>windows</family></os>`.

---

### P3-03 [MEDIUM] [VERIFIED BUG]: Use of `BCryptPasswordEncoder` Instead of Mandated `Argon2id`
- **Issue:** `backend/src/main/java/com/ospysin/identity/config/SecurityConfig.java` declared a `PasswordEncoder` bean using `new BCryptPasswordEncoder()`, whereas `docs/12-DEPLOYMENT.md` and the `web-auth-security` rule require the memory-hard `Argon2id` algorithm.
- **Impact:** Decreased resistance of stored operator password hashes to GPU/ASIC-accelerated offline brute-force attacks compared to the target architecture.
- **Remediation:** Replaced bean instantiation with `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`.

---

### P3-04 [MEDIUM] [UNPROVEN GUARANTEE]: Absence of `ospysin_app` Role Prior to Flyway Migration in Integration Tests
- **Issue:** In `backend/src/test/java/com/ospysin/AbstractIntegrationTest.java`, the PostgreSQL test container was initialized only with the superuser `ospysin_admin`. The application role `ospysin_app` was not created before Flyway executed migrations. As a result, the conditional privilege block in `backend/src/main/resources/db/migration/V1__init_schema.sql` (`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ospysin_app') THEN ...`) was silently skipped. To compensate, `backend/src/test/java/com/ospysin/DatabaseImmutabilityAndPrivilegesIT.java` manually executed `GRANT` and `REVOKE` statements inside the test method, leaving the actual production Flyway migration unverified.
- **Impact:** Unverified automated grant and revocation of table permissions in the Flyway baseline migration.
- **Remediation:** Pre-created `ospysin_app` role inside the static initializer of `AbstractIntegrationTest` before Flyway runs (`CREATE ROLE ospysin_app WITH LOGIN PASSWORD 'app_secret_test'`). Removed manual `GRANT/REVOKE` from `DatabaseImmutabilityAndPrivilegesIT` to validate the migration's native DDL directly.

---

### P3-05 [MEDIUM] [VERIFIED BUG]: Entity Encapsulation Violations and Unsafe JPA Builders
- **Issue:** JPA entities used public `@NoArgsConstructor`, `@AllArgsConstructor`, and class-level `@Setter` annotations, exposing mutation methods on primary keys (`setId`), creation timestamps (`setCreatedAt`), and append-only domain facts (`Evidence`, `Observation`, `ScopeAsset`). Additionally, class-level `@Builder` exposed `id` parameters in generated builders, creating risks of accidental detached entity `merge` rather than `persist` under Hibernate 6.
- **Impact:** Risk of domain model corruption, bypassed WORM immutability guarantees, and improper entity lifecycle management in the persistence context.
- **Remediation:**
  - Enforced `@NoArgsConstructor(access = AccessLevel.PROTECTED)` across all 11 JPA entities.
  - Removed class-level `@AllArgsConstructor`, class-level `@Builder`, and class-level `@Setter`.
  - Marked immutable domain entities (`ScopeAsset`, `ToolResult`, `Observation`, `Evidence`, `AuditEvent`) with `@org.hibernate.annotations.Immutable` and removed all setters.
  - Kept field-level `@Setter` strictly on mutable lifecycle properties of mutable entities (`User`, `Project`, `Engagement`, `AuditSession`, `ToolExecution`, `Finding`), omitting setters on `id`, `createdAt`, and `@ManyToOne` references.
  - Implemented explicit private constructors annotated with `@Builder` on all 11 entities, strictly excluding `UUID id` and assigning null-safe defaults directly in constructor bodies (timestamps default to `Instant.now()`, JSON maps default to `new HashMap<>()`, counters default to `0`, `Finding.confidence` defaults to `TENTATIVE`, and `ToolResult.rawOutput` is capped via `Utf8StringUtils.truncateUtf8(rawOutput, MAX_RAW_OUTPUT_BYTES)`).

---

### P3-06 [LOW] [VERIFIED BUG]: Untyped `AuditEvent.eventType` String Field
- **Issue:** In `backend/src/main/java/com/ospysin/shared/audit/AuditEvent.java`, `eventType` was defined as an untyped `String` without an enum or database `CHECK` constraint. In `FlywaySchemaAndEntitiesIT`, a non-canonical event type `"FINDING_CONFIRMED"` was persisted, violating canonical events specified in `docs/03-DOMAIN-MODEL.md`.
- **Impact:** Risk of inconsistent audit log entries and forensic ledger divergence.
- **Remediation:** Created strongly typed `enum AuditEventType` (11 canonical values), applied `@Enumerated(EnumType.STRING)` to `AuditEvent.eventType`, added database `CHECK` constraint in `V1__init_schema.sql`, and aligned tests with canonical types.

---

### P3-07 [LOW] [VERIFIED BUG]: Missing URL Normalization, Negative Ollama Health Test, and `jacoco:check`
- **Issue:** In `backend/src/main/java/com/ospysin/shared/health/HealthController.java`, `ospysin.ollama.base-url` was concatenated without stripping trailing slashes, leading to malformed URLs like `//api/tags` if configured as `http://127.0.0.1:11434/`. `backend/src/test/java/com/ospysin/shared/health/HealthControllerIT.java` lacked a test verifying behavior when Ollama is unreachable (`status: UP`, `ollama: DOWN`). `backend/pom.xml` lacked a `jacoco:check` goal enforcing coverage thresholds.
- **Impact:** Potential connection failures, untested dependency degradation paths, and missing automated code coverage enforcement.
- **Remediation:** Normalized `ollamaBaseUrl` by stripping trailing slashes in `HealthController`, added negative integration test for unreachable Ollama in `HealthControllerIT`, and added `check` execution to `jacoco-maven-plugin` with phase `verify` and an 80% line coverage threshold.

---

### P3-08 [LOW] [VERIFIED BUG]: Faulty Surefire Test Report Regex in `scripts/bundle-phase.ps1`
- **Issue:** In `scripts/bundle-phase.ps1`, the case-insensitive regex `-match "FAILURE|ERROR"` matched standard passing Surefire summary lines `Tests run: X, Failures: 0, Errors: 0`, causing passing tests to be mistakenly included in the `Failed Test Reports` section of the audit snapshot.
- **Impact:** False positives in audit bundles presenting passing test suites as failing.
- **Remediation:** Updated condition to case-sensitive marker and positive integer matching:
  `if ($rContent -cmatch "<<< FAILURE!|<<< ERROR!" -or $rContent -match "Failures:\s*[1-9]|Errors:\s*[1-9]")`.
