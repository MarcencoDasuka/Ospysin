# Phase 9: Tool Catalog Registry, PostgreSQL Job Queue & SSE Hub — Architectural & Execution Audit Report

**Date:** 2026-10-15  
**Audit Target:** `phase-09-snapshot.md` (Tool Catalog Registry, 3-Phase PostgreSQL Job Queue with Epoch Fencing & Rate Limiting, Step Query API, and AFTER_COMMIT Server-Sent Events Hub)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An architectural, concurrency, and security audit of the Phase 9 implementation identified 5 findings (2 High, 3 Medium) spanning worker race conditions in asynchronous integration tests, AB-BA row lock ordering hazards in task claiming, missing forensic audit events during Phase 2 policy checks, numeric overflow and missing mandatory parameters in tool catalog validation, and missing HTTP integration tests for the SSE event stream endpoint along with IPv6 rate limiter normalization. All 5 findings have been thoroughly verified, remediated, and validated across 238 automated tests with 87% JaCoCo instruction coverage.

---

## Detailed Findings & Remediations

### P9-01 [HIGH] [VERIFIED BUG]: Async Worker Race Condition in `ToolExecutionQueueAndFencingIT` and Unused `claimNextPending()` Recovery
- **Issue:**
  1. In `ToolExecutionWorker`, enqueuing an execution publishes `ToolExecutionEnqueuedEvent`, which triggers `onToolExecutionEnqueued` via `@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)`. This immediately dispatches `executeTask(executionId)` to the background `toolExecutionExecutor` thread pool.
  2. In `ToolExecutionQueueAndFencingIT.asyncAcceptanceAndLifecycle()`, the test triggered `POST .../run` (launching the background worker task) and subsequently invoked `toolExecutionWorker.executeTask(executionId)` synchronously on the test thread. If the background thread claimed the task first, the test thread's `claimExecution()` returned `Optional.empty()` (as status was already `RUNNING`), resulting in an immediate return and an uncoordinated assertion race against the still-running background thread.
  3. In `duplicateActiveExecutionGuard()` and `bolaGuardOnStepDetail()`, calling `toolExecutionTxService.enqueueExecution(...)` also triggered the background worker; the duplicate guard test passed only when execution order caused `HostRateLimiter` to stall the worker for 500ms on `"example.com"`.
  4. In addition, `ToolExecutionTxService.claimNextPending()` (`FOR UPDATE SKIP LOCKED`) was never utilized by the worker to recover orphaned `PENDING` tasks.
- **Impact:** Non-deterministic integration test flakiness and lack of an automated queue drain mechanism for recovering orphaned pending tasks.
- **Remediation:**
  - Added an `AtomicBoolean autoDispatchEnabled` flag with `isAutoDispatchEnabled()` and `setAutoDispatchEnabled(boolean)` in `ToolExecutionWorker`.
  - In `ToolExecutionWorker.onToolExecutionEnqueued()`, wrapped background submission with `if (autoDispatchEnabled.get())`.
  - Added `public int drainPendingQueue()` in `ToolExecutionWorker`, claiming and executing all orphaned `PENDING` tasks via `toolExecutionTxService.claimNextPending(workerId)` in a loop until empty.
  - In `ExecutionWatchdog`, integrated `toolExecutionWorker.drainPendingQueue()` when `autoDispatchEnabled` is true, ensuring orphaned and reclaimed tasks are processed.
  - In `ToolExecutionQueueAndFencingIT`:
    - Added `@BeforeEach` and `@AfterEach` hooks resetting `hostRateLimiter` and restoring `autoDispatchEnabled(true)`.
    - In `asyncAcceptanceAndLifecycle()`, verified true end-to-end async execution on `toolExecutionExecutor` using bounded polling (up to 5 seconds) until `toolExecutionRepository.findById(executionId)` reached `COMPLETED`.
    - In `duplicateActiveExecutionGuard()` and `bolaGuardOnStepDetail()`, set `autoDispatchEnabled(false)` before enqueuing so tasks stay in `PENDING` deterministically.
    - Added test `drainPendingQueueClaimsAndExecutesPendingTask()` asserting that `drainPendingQueue()` claims and executes orphaned tasks with strict lock ordering.

---

### P9-02 [HIGH] [VERIFIED BUG]: Inconsistent Row Lock Ordering in `ToolExecutionTxService.claimExecution()` and `claimNextPending()`
- **Issue:**
  - `enqueueExecution()` and `AuditSessionTxService.abortSession()` acquired pessimistic row locks on `AuditSession` first (`auditSessionRepository.findByIdForUpdate`) and `ToolExecution` second (`toolExecutionRepository.findByIdForUpdate`).
  - In contrast, `claimExecution()` previously acquired the lock on `ToolExecution` first and `AuditSession` second. Additionally, `claimNextPending()` locked `ToolExecution` before delegating to `claimExecution()`.
  - Concurrent execution of `abortSession()` and `claimExecution()` acquired row locks in opposite order, creating an AB-BA deadlock hazard under concurrent operation.
- **Impact:** Risk of PostgreSQL transaction aborts (`PSQLException: ERROR: deadlock detected`) when an operator aborts an active session while background workers are actively claiming enqueued tools.
- **Remediation:**
  - In `ToolExecutionTxService.claimExecution(UUID executionId, UUID workerId)`:
    - First read the execution without locks via `findById(executionId)` to obtain its `sessionId`.
    - Acquired the row lock on `AuditSession` FIRST via `auditSessionRepository.findByIdForUpdate(sessionId)`.
    - Verified `session.getState() == SessionState.ACTIVE` and that no other execution is `RUNNING` in the session.
    - Acquired the row lock on `ToolExecution` SECOND via `toolExecutionRepository.findByIdForUpdate(executionId)`.
  - In `ToolExecutionTxService.claimNextPending(UUID workerId)`:
    - Queried candidate `PENDING` execution IDs without row locks (`findPendingCandidateIds`), filtering out sessions with an active `RUNNING` execution.
    - Delegated task claiming to `claimExecution(candidateId, workerId)` so locks are acquired in strict `AuditSession -> ToolExecution` order.
  - This strictly enforces the global row lock hierarchy (`AuditSession` -> `ToolExecution`) across all transactions, eliminating AB-BA deadlocks.

---

### P9-03 [MEDIUM] [VERIFIED BUG]: Missing `POLICY_EVALUATED` Forensic Audit Event During Phase 2 Tool Execution
- **Issue:**
  - `ToolExecutionWorker.executeClaimed()` executed `decision = policyEngine.evaluate(...)` for network tools prior to execution, but never recorded the resulting `PolicyDecision` into `audit_events` (neither on allow nor on deny).
- **Impact:** Lack of forensic audit evidence that pre-flight scope, mode, and private IP policies were evaluated before socket connection attempts, degrading regulatory non-repudiation.
- **Remediation:**
  - Propagated `decision` (`PolicyDecision`) to `persistSuccess()` and `persistFailure()` in `ToolExecutionTxService`.
  - In `persistSuccess()` and `persistFailure()`, invoked `policyEngine.recordAudit(execution.getSession(), policyDecision)` inside the Phase 3 database transaction whenever `policyDecision != null`.
  - Added assertions in `ToolExecutionQueueAndFencingIT.asyncAcceptanceAndLifecycle()` verifying `AuditEventType.POLICY_EVALUATED` is persisted on successful tool execution, and added test `policyDenialRecordsAuditEventAndFails()` verifying that policy denial transitions the task to `FAILED` (`failureReason = "POLICY_DENIED"`) and logs the `POLICY_EVALUATED` event.

---

### P9-04 [MEDIUM] [VERIFIED BUG]: `ToolCatalogRegistry` Numeric and Mandatory Validation Edge Cases
- **Issue:**
  - In `ToolCatalogRegistry.parseInteger()`, numbers were cast via `((Number) value).intValue()` directly after checking `instanceof Number`. If a client supplied a floating-point number (e.g. `80.5`) or an overflowing Long (e.g. `4294967376L`), `intValue()` silently truncated the decimals or wrapped around modulo $2^{32}$, causing `4294967376L` to evaluate to `2000` (a valid port) and bypassing port validation.
  - Tools requiring dependent step output (`security_headers_score` and `cve_matcher`) accepted empty parameter maps without validating that mandatory `stepId` was provided.
  - Tools accepting lists (`sensitive_files_check.customPaths`) did not validate `instanceof List<?>`.
- **Impact:** Invalid or overflowed numeric parameters could bypass validation; tools requiring previous step output failed unexpectedly during Phase 2 execution rather than being rejected at ingestion time with `422 Unprocessable Entity`.
- **Remediation:**
  - In `ToolCatalogRegistry.parseInteger()`:
    - Explicitly rejected `Double` and `Float` instances as invalid integer inputs.
    - Checked `longVal < Integer.MIN_VALUE || longVal > Integer.MAX_VALUE` before casting, throwing `ValidationException` on overflow.
  - Enforced mandatory `stepId` parameter presence and valid UUID format for `security_headers_score` and `cve_matcher`.
  - Added `instanceof List<?>` validation for `customPaths` in `sensitive_files_check`.
  - Added comprehensive unit tests in `ToolCatalogRegistryTest` covering float rejection, Long overflow rejection, missing `stepId`, and non-list `customPaths`.

---

### P9-05 [MEDIUM] [VERIFIED BUG]: Missing Integration Test for `GET /api/sessions/{id}/events` SSE Endpoint & IPv6 Normalization
- **Issue:**
  - While `SessionSseHubTest` unit tested the SSE hub lifecycle in isolation, there was no integration test validating the HTTP SSE endpoint contract (`GET /api/sessions/{id}/events`): verifying `200 OK` with `text/event-stream`, `404 Not Found` for non-existent session, and `401 Unauthorized` for unauthenticated requests.
  - In `HostRateLimiter.normalizeHost()`, a naive `indexOf(':')` stripped unbracketed IPv6 addresses (e.g. `2001:db8::1`) down to `2001`.
- **Impact:** Unverified SSE endpoint routing and security contracts, and incorrect rate limiting for IPv6 target hosts.
- **Remediation:**
  - Updated `HostRateLimiter.normalizeHost()` and `ToolExecutionWorker.extractHost()` to only strip `:port` when `firstColon == lastColon` or after a closing bracket `]`, preserving IPv6 addresses.
  - Added unit test `normalizesIpv6Hosts()` in `HostRateLimiterTest`.
  - Created `SessionSseControllerIT` with integration tests verifying `401 Unauthorized` when unauthenticated, `404 Not Found` ProblemDetail for missing sessions, and `200 OK` with `text/event-stream` for active sessions.
