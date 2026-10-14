# Phase 7: Audit Session Lifecycle & Scope Attestation API — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-07-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-07-snapshot.md`  

---

## Remediation Checklist

- [x] **P7-01 [MEDIUM] [VERIFIED BUG]**: Record rejected pre-flight policy evaluations to `audit_events` via `policyEngine.recordAudit(null, decision)` in `AuditSessionService.createSession()`, add `findBySessionIsNull()` in `AuditEventRepository`, and assert forensic event persistence.
- [x] **P7-02 [MEDIUM] [VERIFIED BUG]**: Add `@Size(max = 500)` on `targetUrl` and `@Size(max = 20)` on `scopeAckVersion` in `CreateSessionRequest`, enforce RFC 1035 host length limit (253 chars max) in `PolicyEngine.evaluateUri()`, and truncate engagement title to 150 chars max in `AuditSessionTxService.initializeSession()`.
- [x] **P7-03 [LOW] [VERIFIED BUG]**: Exclude `FindingStatus.REJECTED` false-positive findings from `findingCount` in `FindingRepository` (`countBySessionIdAndStatusNot` and updated `countFindingsBySessionIds` query), session response DTOs, and lifecycle transitions.
- [x] **P7-04 [LOW] [VERIFIED INCONSISTENCY]**: Track post-audit finding `P6-06` in `docs/audits/phase-06-audit.md` and `docs/remediation/phase-06-remediation.md`, and create `docs/audits/phase-07-audit.md` and `docs/remediation/phase-07-remediation.md`.

---

## Verification Summary

- **Backend Tests Executed:** 204/204 passed (`mvnw.cmd test` / `mvnw.cmd clean verify`).
  - `ScopeAttestationRegistryTest`: 6/6 passed
  - `AuditSessionServiceTest`: 4/4 passed
  - `AuditSessionControllerIT`: 9/9 passed
  - `PolicyEngineTest`: 35/35 passed
  - Pre-existing regression suites: `IpRangeValidatorTest` (65/65), `ObfuscatedIpParserTest` (24/24), `CidrBlockTest` (19/19), `PayloadLimitGuardTest` (7/7), `AuthControllerIT` (7/7), `GlobalExceptionHandlerTest` (7/7), `Utf8ByteTruncationTest` (7/7), `DatabaseImmutabilityAndPrivilegesIT` (4/4), `FlywaySchemaAndEntitiesIT` (3/3), `PinnedDnsResolverTest` (3/3), `HealthControllerIT` (2/2), `SystemDnsResolverTest` (2/2).
- **JaCoCo Coverage:** All coverage checks met (>= 80% line and branch coverage enforced by jacoco-maven-plugin).
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-07-snapshot.md`.
