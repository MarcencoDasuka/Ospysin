# Phase 7: Audit Session Lifecycle & Scope Attestation API — Architectural & Security Audit Report

**Date:** 2026-10-14  
**Audit Target:** `phase-07-snapshot.md` (Audit session REST API, server-authoritative scope attestation gate, lifecycle state machine, pessimistic row-locking, worker epoch fencing)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An architectural, security, and algorithmic audit of the Phase 7 implementation identified 4 findings (2 Medium, 2 Low) spanning missing forensic audit logs on pre-flight policy denials, missing Bean Validation size constraints and DNS host length limits, false-positive finding inflation in session summary statistics, and audit documentation synchronizations. All 4 findings have been verified, remediated, and validated through automated unit and integration tests.

---

## Detailed Findings & Remediations

### P7-01 [MEDIUM] [VERIFIED BUG]: Rejected Pre-Flight Policy Evaluations Not Logged to `audit_events`
- **Issue:** When `policyEngine.evaluate(request.targetUrl(), request.mode(), null)` returned `allowed == false`, `AuditSessionService.createSession()` immediately threw `PolicyViolationException` without invoking `policyEngine.recordAudit(null, decision)`.
- **Impact:** Failed pre-session policy evaluations (e.g. operators probing prohibited internal networks or loopback in PUBLIC mode) left no forensic footprint in the immutable audit trail, contrary to the legal ledger specifications in `docs/09-LEGAL-AND-ETHICS.md`.
- **Remediation:**
  - In `AuditSessionService.createSession()`, invoked `policyEngine.recordAudit(null, decision)` before throwing `PolicyViolationException`.
  - Added `findBySessionIsNull()` to `AuditEventRepository`.
  - Added an assertion in `AuditSessionControllerIT.createSessionPublicModeRejectsPrivateIps()` verifying that a `POLICY_EVALUATED` event with `session == null` and `allowed == false` is stored in `audit_events`.
  - Updated `AuditSessionServiceTest.createSessionPolicyViolation()` to verify `policyEngine.recordAudit(null, decision)` is called.

---

### P7-02 [MEDIUM] [VERIFIED BUG]: Missing `@Size` Bounds, RFC 1035 Host Length Guard, and Unbounded Engagement Title
- **Issue:** `targetUrl` and `scopeAckVersion` lacked `@Size` bounds in `CreateSessionRequest`, host length was not constrained against the RFC 1035 limit of 253 characters in `PolicyEngine`, and the generated engagement title (`"Ad-Hoc Audit: " + targetHost`) in `AuditSessionTxService` could exceed the 150-character schema limit.
- **Impact:** Submitting oversized strings could trigger raw database `DataIntegrityViolationException` (HTTP 500) instead of clean HTTP 422 Problem Details or HTTP 403 policy rejection.
- **Remediation:**
  - Added `@Size(max = 500)` to `targetUrl` and `@Size(max = 20)` to `scopeAckVersion` in `CreateSessionRequest`.
  - Added an RFC 1035 host length guard in `PolicyEngine.evaluateUri()` rejecting hosts longer than 253 characters with `PolicyDecision(false, "Target host exceeds maximum DNS length of 253 characters", ...)`.
  - Truncated generated engagement title to 150 characters max in `AuditSessionTxService.initializeSession()`.
  - Added test cases in `AuditSessionControllerIT` (oversized URL > 500 characters returning 422) and `PolicyEngineTest` (host > 253 characters rejected).

---

### P7-03 [LOW] [VERIFIED BUG]: `findingCount` in Session Metadata Included `REJECTED` Findings
- **Issue:** `FindingRepository.countBySessionId()` and `countFindingsBySessionIds()` counted all finding records regardless of status, including operator-dismissed false positives marked `FindingStatus.REJECTED`.
- **Impact:** Session summaries in `GET /api/sessions` and `GET /api/sessions/{id}` reported inflated active finding counts.
- **Remediation:**
  - Added `FindingRepository.countBySessionIdAndStatusNot(sessionId, FindingStatus.REJECTED)`.
  - Updated `countFindingsBySessionIds()` JPQL query to filter `WHERE f.status <> com.ospysin.findings.FindingStatus.REJECTED`.
  - Updated `AuditSessionService.getSession()` and `AuditSessionTxService` (`completeSession`, `abortSession`) to exclude `REJECTED` findings.
  - Updated `AuditSessionControllerIT.querySessionsAndMetadata()` to seed both `CONFIRMED` and `REJECTED` findings and assert `findingCount == 1`.

---

### P7-04 [LOW] [VERIFIED INCONSISTENCY]: Phase 6 and Phase 7 Audit/Remediation Documentation Tracking
- **Issue:** Post-audit finding `P6-06` (IPv6 normalization in `PolicyEngine.extractHost()` and `evaluateUri()`) was implemented but not formally tracked in `docs/audits/phase-06-audit.md` and `docs/remediation/phase-06-remediation.md`. Phase 7 audit and remediation tracking documents were absent.
- **Impact:** Discrepancy between code changes, test counts (34 in `PolicyEngineTest`, 184 pre-Phase 7 backend tests), and audit records.
- **Remediation:**
  - Updated `docs/audits/phase-06-audit.md` and `docs/remediation/phase-06-remediation.md` documenting `P6-06` and updated test counts.
  - Created `docs/audits/phase-07-audit.md` and `docs/remediation/phase-07-remediation.md` tracking `P7-01` through `P7-04`.
