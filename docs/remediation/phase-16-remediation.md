# Phase 16: Active Vulnerability & Exploit Surface Probes (`sensitive_files_check`, `js_secrets_scanner`, `cors_misconfig_check`, `subdomain_takeover_check`) — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-16-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-16-snapshot.md`  

---

## Remediation Checklist

- [x] **P16-01 [HIGH] [RATE LIMITING / OPERATIONAL SAFETY]**: Enforce `HostRateLimiter` across multi-request probe loops in `SensitiveFilesCheckTool.java`, `JsSecretsScannerTool.java`, `CorsMisconfigCheckTool.java`, and `SubdomainTakeoverCheckTool.java`:
  - Injected `HostRateLimiter` via constructor injection in all four active probe tools.
  - Added `hostRateLimiter.acquire(targetHost)` before every outbound HTTP request in probe loops.
  - Injected mock/test instances of `HostRateLimiter` in unit test classes (`SensitiveFilesCheckToolTest`, `JsSecretsScannerToolTest`, `CorsMisconfigCheckToolTest`, `SubdomainTakeoverCheckToolTest`) and verified invocations with `Mockito.verify(hostRateLimiter, Mockito.atLeastOnce()).acquire(...)`.
- [x] **P16-02 [MEDIUM] [RESOURCE GOVERNANCE / 4-TIER BOUNDS]**: Distinguish per-file limit vs Tier-3 aggregate budget in `JsSecretsScannerTool.java`:
  - When catching `PayloadLimitExceededException` in the bundle download loop, evaluated whether the aggregate budget was exceeded (`aggregateBudget.getConsumedBytes() > aggregateBudget.getMaxBytes()` or message contains `"Aggregate payload budget exceeded"`).
  - If aggregate budget exceeded: logged warning, recorded `"STOPPED: Aggregate payload budget exceeded"` in raw trace, and terminated loop (`break`).
  - If single-file limit exceeded: recorded `"SKIPPED (File payload limit exceeded): " + jsUrl` in raw trace, and continued (`continue`) scanning remaining bundles.
  - Added regression test `continuesScanningRemainingFilesWhenSingleFileExceedsLimit` and verified `stopsDownloadWhenAggregateBudgetExceeded` in `JsSecretsScannerToolTest.java`.
- [x] **P16-03 [MEDIUM] [PROTOCOL PARSING & SCOPE CONTAINMENT]**: IPv6 host extraction and CNAME private IP policy enforcement in `SubdomainTakeoverCheckTool.java`:
  - Hardened `extractHost` to handle bracketed IPv6 literals (`[::1]`), strip query/fragments, and strip trailing root dots.
  - Added regression test `extractHostHandlesBracketedIpv6` in `SubdomainTakeoverCheckToolTest.java`.
  - Added regression test `policyBlockedWhenCnameResolvesToPrivateIpInPublicMode` in `SubdomainTakeoverCheckToolTest.java` verifying that `PolicyEngine` blocks outbound probes to private IPs when operating in public mode.
- [x] **P16-04 [LOW] [INPUT VALIDATION & RFC 6454 COMPLIANCE]**: Reject explicit `null` parameters and skip IPv6 origin bypass permutations in `CorsMisconfigCheckTool.java`:
  - Enforced explicit `null` rejection in `ToolCatalogRegistry.java` and all tool parameter validators (`customPaths`, `stopOnFirstExposed`, `jsUrls`, `maxFiles`, `customOrigins`, `subdomains`).
  - In `CorsMisconfigCheckTool.java`, skipped prefix and suffix origin mutation probes when `targetHost` contains IPv6 colons or brackets to prevent malformed origin headers.
  - Added regression tests `validateParamsRejectsExplicitNullParameters` in `ToolCatalogRegistryTest.java` and `skipsPrefixSuffixProbesForIpv6TargetHost` in `CorsMisconfigCheckToolTest.java`.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 390/390 passed across all test suites (`.\mvnw.cmd test`):
  - `SensitiveFilesCheckToolTest`: 6/6 passed.
  - `JsSecretsScannerToolTest`: 6/6 passed.
  - `CorsMisconfigCheckToolTest`: 6/6 passed.
  - `SubdomainTakeoverCheckToolTest`: 6/6 passed.
  - `ToolCatalogRegistryTest`: 12/12 passed.
  - All existing 354 core backend tests passed.
  - JaCoCo instruction coverage gate met ($\ge 80\%$).
- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm.cmd test:run`).
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-16-snapshot.md`.
