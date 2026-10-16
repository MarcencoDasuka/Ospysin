# Phase 16: Active Vulnerability & Exploit Surface Probes (`sensitive_files_check`, `js_secrets_scanner`, `cors_misconfig_check`, `subdomain_takeover_check`) — Architectural & Security Audit Report

**Date:** 2026-10-16  
**Audit Target:** `phase-16-snapshot.md` (`SensitiveFilesCheckTool`, `JsSecretsScannerTool`, `CorsMisconfigCheckTool`, `SubdomainTakeoverCheckTool`, `HostRateLimiter` multi-request loop enforcement, 4-tier payload boundaries, aggregate vs per-file budget handling, IPv6 host extraction, origin validation, magic-byte signatures, secret masking)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An adversarial security and architectural audit of Phase 16 evaluated the implementation of the final four active vulnerability probes completing the 15-tool Ospysin Tool Catalog:
1. **`SensitiveFilesCheckTool` (`sensitive_files_check`)**: Active prober for exposed environment files (`.env`), version control metadata (`.git/HEAD`, `.git/config`), backups (`.bak`, `.zip`), configuration files, and Spring Boot Actuators (`/actuator/env`, `/actuator/health`), using magic-byte and content signature verification to eliminate soft-404 false positives, accompanied by snippet credential masking.
2. **`JsSecretsScannerTool` (`js_secrets_scanner`)**: Scanner for client-side JavaScript bundles (sourced from inputs, prior `extract_js_urls` steps, or HTML harvesting) enforcing the 4-tier payload budget (1 MB wire cap, 2 MB decompressed cap per file, 5 MB aggregate budget), scanning for leaked API tokens, private keys, and high-entropy credentials with middle-character masking.
3. **`CorsMisconfigCheckTool` (`cors_misconfig_check`)**: Assesses Cross-Origin Resource Sharing (CORS) policies using arbitrary origins, `null` origins, prefix bypasses, and suffix bypasses, flagging exploitable origin reflections combined with `Access-Control-Allow-Credentials: true`.
4. **`SubdomainTakeoverCheckTool` (`subdomain_takeover_check`)**: Examines CNAME records of candidate subdomains for dangling aliases pointing to known cloud providers (AWS S3, GitHub Pages, Heroku, Azure, Zendesk, Fastly) and probes unclaimed fingerprints via policy-approved IP pinning.

The audit identified 4 findings (1 High, 2 Medium, 1 Low). All 4 findings have been remediated and verified with **390 backend Maven tests** (0 failures, 0 errors, 0 skipped) and **116 frontend Vitest tests**, with clean type-checking and production bundling (`vue-tsc --noEmit && vite build`).

---

## Detailed Findings & Remediations

### P16-01 [HIGH] [RATE LIMITING / OPERATIONAL SAFETY]: Missing `HostRateLimiter` Enforcement in Multi-Request Probe Loops
- **Issue:**
  - `ToolExecutionWorker` invokes `hostRateLimiter.acquire(targetHost)` once before calling `tool.execute(context)`.
  - However, all four Phase 16 tools execute loops performing multiple sequential HTTP requests against target hosts:
    - `SensitiveFilesCheckTool`: probes up to 30 curated sensitive paths.
    - `JsSecretsScannerTool`: downloads up to 50 JavaScript bundles.
    - `CorsMisconfigCheckTool`: tests arbitrary, `null`, prefix, suffix, and custom origins.
    - `SubdomainTakeoverCheckTool`: resolves and probes multiple candidate subdomains.
  - Without enforcing `hostRateLimiter.acquire(...)` inside these loops, subsequent requests within a single tool run fired without token pacing, exceeding target host rate limits (default 2 req/sec, minimum 500ms delay), risking defensive IP bans or target instability.
- **Impact:** Violation of rate limiting invariants during multi-request active probes.
- **Remediation:**
  - Injected `HostRateLimiter` into the constructors of `SensitiveFilesCheckTool`, `JsSecretsScannerTool`, `CorsMisconfigCheckTool`, and `SubdomainTakeoverCheckTool`.
  - Added `hostRateLimiter.acquire(targetHost)` prior to every outbound HTTP probe in each tool's iteration loop.
  - Provided test-friendly mockable constructors in test suites (`SensitiveFilesCheckToolTest`, `JsSecretsScannerToolTest`, `CorsMisconfigCheckToolTest`, `SubdomainTakeoverCheckToolTest`), verifying `Mockito.verify(hostRateLimiter, Mockito.atLeastOnce()).acquire(...)` without introducing artificial 500ms test delays.

---

### P16-02 [MEDIUM] [RESOURCE GOVERNANCE / 4-TIER BOUNDS]: Conflation of Single-File Limit with Aggregate Budget in `JsSecretsScannerTool`
- **Issue:**
  - In `JsSecretsScannerTool`, when downloading JavaScript bundles under `PayloadLimitGuard`, catching `PayloadLimitExceededException` previously triggered an immediate `break` statement, halting all remaining bundle downloads.
  - If bundle #1 exceeded the single-file wire limit (1 MB) or decompressed limit (2 MB) or triggered decompression bomb protection, the tool halted scanning completely, even though the overall 5 MB aggregate budget (`AggregatePayloadBudget`) still had ample capacity to scan subsequent valid bundles.
- **Impact:** False negatives in secret detection; failure to scan smaller bundles after encountering one oversized file.
- **Remediation:**
  - Updated the exception handling in `JsSecretsScannerTool.execute()`:
    - Inspects whether the aggregate budget was exhausted: `aggregateBudget.getConsumedBytes() > aggregateBudget.getMaxBytes()` or `plee.getMessage().contains("Aggregate payload budget exceeded")`.
    - If the aggregate budget was exhausted: logs a warning, appends `"STOPPED: Aggregate payload budget exceeded"` to `rawTrace`, and terminates the loop (`break`).
    - If only the individual file exceeded limits (or triggered decompression bomb protection): appends `"SKIPPED (File payload limit exceeded): " + jsUrl` to `rawTrace`, and continues (`continue`) scanning remaining in-scope bundles.
  - Updated `stopsDownloadWhenAggregateBudgetExceeded` in `JsSecretsScannerToolTest` to execute `tool.execute(context)` and verify the `STOPPED` outcome. Added `continuesScanningRemainingFilesWhenSingleFileExceedsLimit` verifying that bundle #2 is scanned and its secrets flagged even if bundle #1 exceeds single-file limits.

---

### P16-03 [MEDIUM] [PROTOCOL PARSING & SCOPE CONTAINMENT]: IPv6 Host Extraction & CNAME Private IP Policy Enforcement in `SubdomainTakeoverCheckTool`
- **Issue:**
  - `SubdomainTakeoverCheckTool.extractHost()` split strings naively on `:` and `/`, which corrupted bracketed IPv6 target literals (e.g., `http://[::1]:8080/`), causing invalid domain lookups.
  - In addition, when candidate CNAME records resolve to private/loopback IP addresses while operating in `PUBLIC` mode, `PolicyEngine` must block outbound HTTP connections with a `POLICY_BLOCKED` outcome. A regression test verifying this protection was absent.
- **Impact:** Failed host extraction for IPv6 addresses and unverified SSRF defense on dangling CNAME targets.
- **Remediation:**
  - Hardened `extractHost` in `SubdomainTakeoverCheckTool`:
    - Stripped query (`?`) and fragment (`#`) delimiters.
    - Handled bracketed IPv6 literals `[ipv6]` correctly, extracting the enclosed host.
    - Stripped ports and trailing root dots (`.`).
  - Added `extractHostHandlesBracketedIpv6` in `SubdomainTakeoverCheckToolTest`.
  - Added `policyBlockedWhenCnameResolvesToPrivateIpInPublicMode` in `SubdomainTakeoverCheckToolTest`, verifying that when a CNAME points to an RFC 1918 address in `PUBLIC` mode, `PolicyEngine` blocks the probe with `status = "POLICY_BLOCKED"`.

---

### P16-04 [LOW] [INPUT VALIDATION & RFC 6454 COMPLIANCE]: Explicit `null` Parameter Handling & IPv6 Origin Formatting in `CorsMisconfigCheckTool`
- **Issue:**
  - `ToolCatalogRegistry.validateParams` and probe-specific `validateParams` permitted explicit JSON `null` values for optional parameters (e.g., `"customPaths": null`, `"stopOnFirstExposed": null`, `"jsUrls": null`, `"maxFiles": null`, `"customOrigins": null`, `"subdomains": null`), leading to potential `NullPointerException` during execution.
  - In `CorsMisconfigCheckTool`, prefix and suffix bypass origin mutations (e.g., `https://attacker.com.` + `targetHost`) were generated even when `targetHost` was an IPv6 address containing `:` or brackets, resulting in malformed RFC 6454 `Origin` headers like `https://attacker.com.[::1]`.
- **Impact:** Parameter validation gaps and malformed HTTP `Origin` headers on IPv6 targets.
- **Remediation:**
  - Enforced explicit `null` rejection in `ToolCatalogRegistry.validateParams` and in all tool `validateParams` methods with informative validation error messages.
  - In `CorsMisconfigCheckTool`, skipped prefix and suffix origin mutation probes when `targetHost` contains IPv6 colons (`:`) or brackets (`[`/`]`), testing only arbitrary origin, `null` origin, and valid custom origins.
  - Added `validateParamsRejectsExplicitNullParameters` in `ToolCatalogRegistryTest` and `skipsPrefixSuffixProbesForIpv6TargetHost` in `CorsMisconfigCheckToolTest`.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 390/390 passed across all test suites (`.\mvnw.cmd test`):
  - `SensitiveFilesCheckToolTest`: 6/6 passed (exposed file detection, magic byte verification, 404/soft-404 rejection, rate limiter acquisition, null parameter rejection, secret masking).
  - `JsSecretsScannerToolTest`: 6/6 passed (token/secret detection, entropy detection, aggregate budget termination, per-file skip and continue, rate limiter acquisition, null parameter rejection).
  - `CorsMisconfigCheckToolTest`: 6/6 passed (ACAC reflection detection, null origin detection, IPv6 origin bypass skipping, rate limiter acquisition, null parameter rejection, safe origin handling).
  - `SubdomainTakeoverCheckToolTest`: 6/6 passed (fingerprint matching, CNAME resolution, policy blocked on private IP CNAME, IPv6 host extraction, rate limiter acquisition, null parameter rejection).
  - `ToolCatalogRegistryTest`: 12/12 passed (including explicit null rejection across all 15 tools).
  - All existing 354 core backend tests passed.
  - JaCoCo instruction coverage gate met ($\ge 80\%$).
- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm.cmd test:run`).
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-16-snapshot.md`.
