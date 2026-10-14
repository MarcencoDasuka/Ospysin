# Phase 9: Tool Catalog Registry, PostgreSQL Job Queue & SSE Hub — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-09-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-09-snapshot.md`  

---

## Remediation Checklist

- [x] **P9-01 [HIGH] [VERIFIED BUG]**: Prevent async worker race conditions in `ToolExecutionQueueAndFencingIT` by adding `autoDispatchEnabled` flag and `drainPendingQueue()` recovery method in `ToolExecutionWorker`, integrating queue drain into `ExecutionWatchdog`, adopting bounded polling in `asyncAcceptanceAndLifecycle()`, disabling auto-dispatch in duplicate guard and BOLA tests, and testing `drainPendingQueue()` with strict lock ordering.
- [x] **P9-02 [HIGH] [VERIFIED BUG]**: Eliminate AB-BA deadlock hazard by enforcing a strict global row lock ordering in `ToolExecutionTxService.claimExecution()`: reading the uncommitted execution to discover `sessionId`, acquiring `AuditSession` lock FIRST via `auditSessionRepository.findByIdForUpdate()`, and acquiring `ToolExecution` lock SECOND via `toolExecutionRepository.findByIdForUpdate()`.
- [x] **P9-03 [MEDIUM] [VERIFIED BUG]**: Record forensic `POLICY_EVALUATED` audit event during Phase 2 execution by passing `PolicyDecision` into `persistSuccess()` and `persistFailure()` in `ToolExecutionTxService`, calling `policyEngine.recordAudit(session, decision)` within the Phase 3 transaction, and verifying audit event persistence on both allow and deny paths in `ToolExecutionQueueAndFencingIT`.
- [x] **P9-04 [MEDIUM] [VERIFIED BUG]**: Harden `ToolCatalogRegistry` input validation by rejecting floating-point numbers (`Double`/`Float`) and Long overflow in `parseInteger()`, enforcing mandatory `stepId` UUID parameter presence for `security_headers_score` and `cve_matcher`, validating list types for `customPaths`, and adding comprehensive unit tests in `ToolCatalogRegistryTest`.
- [x] **P9-05 [MEDIUM] [VERIFIED BUG]**: Preserve unbracketed and bracketed IPv6 target addresses in `HostRateLimiter.normalizeHost()` and `ToolExecutionWorker.extractHost()`, add unit test coverage in `HostRateLimiterTest`, and create `SessionSseControllerIT` verifying `401 Unauthorized`, `404 Not Found`, and `200 OK` `text/event-stream` for `GET /api/sessions/{id}/events`.

---

## Verification Summary

- **Backend Tests Executed:** 238/238 passed across all suites (`mvnw.cmd clean verify`):
  - `ToolExecutionQueueAndFencingIT`: 9/9 passed (async acceptance with bounded polling, BOLA guard, duplicate active execution guard, epoch fencing, watchdog expiration, drain pending queue with strict lock ordering, policy denial audit event recording, input validation 400 & 422).
  - `SessionSseControllerIT`: 3/3 passed (unauthenticated 401, non-existent session 404, active session 200 text/event-stream).
  - `SessionSseHubTest`: 4/4 passed (subscribe, remove, broadcast without subscribers, event listener delegation).
  - `HostRateLimiterTest`: 6/6 passed (rate limit and spacing enforcement, independent host limits, port/protocol normalization, bucket reset, null/blank safety, IPv6 bracketed/unbracketed normalization).
  - `ToolCatalogRegistryTest`: 10/10 passed (15 canonical tools metadata, valid params, unknown tool 400, invalid port range, invalid stepId format, invalid maxUrls range, custom tool bean delegation, float and Long overflow rejection, mandatory stepId requirement, non-list rejection).
  - `ToolCatalogControllerIT`: 2/2 passed (`GET /api/tools` authenticated 200 with 15 tools, unauthenticated 401).
  - Pre-existing regression suites: 204/204 passed (Sessions, Engagements, Projects, Scope, PolicyEngine, Identity, Audit, Findings, Evidence, Health).
- **Code Coverage:** JaCoCo instruction coverage of **87%** (7,710 of 8,815 instructions covered) and line coverage of **88%** (1,671 of 1,901 lines covered) across 85 classes, comfortably exceeding the >=80% project threshold.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-09-snapshot.md`.
