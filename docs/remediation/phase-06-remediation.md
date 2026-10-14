# Phase 6: Network Policy Engine & SSRF / DNS Rebinding Guard — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-06-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-06-snapshot.md`  

---

## Remediation Checklist

- [x] **P6-01 [HIGH] [VERIFIED BUG]**: Replace unconditional scope bypass in `PolicyEngine.isWithinScope()` with `CNAME_TAKEOVER_PROVIDER_SUFFIXES` allowlist matching and reject unrelated domains when `isSubdomainTakeoverCheck == true`.
- [x] **P6-02 [MEDIUM] [VERIFIED BUG]**: Unwrap deprecated IPv4-compatible IPv6 addresses (`::/96`) and add special-purpose IPv6 transition ranges (`64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `100::/64`, `2001:2::/48`, `2001:10::/28`) to `UNCONDITIONAL_BLOCKED_CIDRS`.
- [x] **P6-03 [MEDIUM] [VERIFIED BUG]**: Fall back to `uri.getRawAuthority()` when `uri.getHost()` is null for dotted-hex/short numeric IP literals, validate extracted ports against `ALLOWED_PORTS`, and strip trailing root FQDN dots (`.`).
- [x] **P6-04 [LOW] [VERIFIED INCONSISTENCY]**: Populate `List.of(new InvalidParam("targetUrl", decision.reason()))` in `PolicyEngine.enforce()` for RFC 9457 compliance.
- [x] **P6-05 [LOW] [VERIFIED BUG]**: Replace live external DNS domain query with `"999.999.999.999"` in `SystemDnsResolverTest` to eliminate 11-second test timeout.

---

## Verification Summary

- **Backend Tests Executed:** 183/183 passed (`mvnw.cmd test` / `mvnw.cmd clean verify`).
  - `IpRangeValidatorTest`: 65/65 passed (RFC 6890, cloud metadata, NAT64, 6to4, Discard-Only, IPv4-mapped & IPv4-compatible unwrapping).
  - `PolicyEngineTest`: 37/37 passed (scheme/port allowlist, userinfo, multi-IP DNS, scope containment, CNAME takeover allowlist, dotted-hex/short IP authority fallback, trailing dots, redirect hop cap, DNS rebinding harness, invalidParams).
  - `ObfuscatedIpParserTest`: 24/24 passed (octal, hex, dword, dotted, bracketed IPv6, trailing dot stripping).
  - `PayloadLimitGuardTest`: 7/7 passed (Tier 1 wire cap, Tier 2 decompressed cap, Tier 2 expansion ratio threshold, live gzip bomb, Tier 3 aggregate budget).
  - `CidrBlockTest`: 19/19 passed (bitwise CIDR matching, invalid CIDRs, boundary and cross-family checks).
  - `PinnedDnsResolverTest`: 3/3 passed (hostname pinning, wildcard pinning, parameter validation).
  - `SystemDnsResolverTest`: 2/2 passed (local resolution and immediate non-network invalid IP rejection).
  - Integration Tests: `DatabaseImmutabilityAndPrivilegesIT`, `FlywaySchemaAndEntitiesIT`, `AuthControllerIT`, `HealthControllerIT`, `GlobalExceptionHandlerTest`, `Utf8ByteTruncationTest` all passed.
- **JaCoCo Coverage:** All coverage checks met (>= 80% line coverage enforced by maven-surefire and jacoco-maven-plugin).
- **Execution Latency:** Test execution time optimized from 56s to 30s.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-06-snapshot.md`.
