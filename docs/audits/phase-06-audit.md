# Phase 6: Network Policy Engine & SSRF / DNS Rebinding Guard — Architectural & Security Audit Report

**Date:** 2026-10-14  
**Audit Target:** `phase-06-snapshot.md` (Deterministic network safety engine, IANA RFC 6890 CIDR filtering, IP pinning `DnsResolver`, 4-tier payload boundaries & decompression bomb guard)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An architectural, security, and algorithmic audit of the Phase 6 implementation identified 6 findings (1 High, 3 Medium, 2 Low) spanning scope containment bypasses during subdomain takeover checks, special-purpose IPv6 transition range gaps and IPv4-compatible unwrapping, URI parser host extraction edge cases with dotted-hex and short numeric IP literals, missing RFC 9457 `invalidParams` details in policy exception enforcement, an 11-second test suite delay caused by live external DNS resolution, and IPv6 host/port normalization edge cases. All 6 findings have been verified, remediated, and covered by automated unit tests.

---

## Detailed Findings & Remediations

### P6-01 [HIGH] [VERIFIED BUG]: Unconditional Scope Bypass in `PolicyEngine.isWithinScope()` during Subdomain Takeover Probes
- **Issue:** In `PolicyEngine.java`, when evaluating target hosts with `isSubdomainTakeoverCheck == true`, the conditional check `if (normalizedTarget.endsWith("." + scopeHost)) { return true; }` was immediately followed by an unconditional `return true;`. This made the conditional check dead code and allowed any arbitrary external domain (e.g. `https://unrelated-evil.org`) to bypass scope containment when the subdomain takeover flag was enabled.
- **Impact:** Critical scope containment boundary failure allowing unauthorized external hosts to pass scope checks during subdomain takeover probe evaluations.
- **Remediation:**
  - Defined `CNAME_TAKEOVER_PROVIDER_SUFFIXES` containing the canonical cloud provider CNAME suffixes specified in `docs/05-TOOL-CATALOG.md` (`.s3.amazonaws.com`, `.amazonaws.com`, `.github.io`, `.herokuapp.com`, `.vercel.app`, `.azurewebsites.net`, `.cloudfront.net`, `.fastly.net`).
  - Updated `PolicyEngine.isWithinScope()` to permit external destinations ONLY if the target host is a subdomain/exact match of `scopeHost` OR matches one of the canonical CNAME provider suffixes, returning `false` for all other domains.
  - Added an assertion in `PolicyEngineTest.subdomainTakeoverRule()` verifying that unrelated external domains (e.g., `https://unrelated-evil.org`) are rejected with `"outside authorized scope"` even when `isSubdomainTakeoverCheck == true`.

---

### P6-02 [MEDIUM] [VERIFIED BUG]: Unhandled IPv6 Transition Ranges (NAT64, 6to4, Discard-Only, Benchmarking) and Incomplete Deprecated IPv4-Compatible IPv6 Address Unwrapping
- **Issue:** `IpRangeValidator` previously only unwrapped IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) and blocked `::/128`. Deprecated IPv4-compatible IPv6 addresses (`::127.0.0.1`, `::169.254.169.254`), NAT64 translation ranges (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 translation (`2002::/16`), Discard-Only (`100::/64`), and BMWG benchmarking (`2001:2::/48`) were not blocked or unwrapped.
- **Impact:** Potential SSRF evasion via IPv6 transition or compatibility representations on dual-stack hosts.
- **Remediation:**
  - Updated `IpRangeValidator.unwrapIpv4Mapped()` to unwrap deprecated IPv4-compatible IPv6 addresses in `::/96` (first 12 bytes `0x00`), while strictly preserving `::` (unspecified) and `::1` (loopback) as pure IPv6 addresses.
  - Added `64:ff9b::/96` (NAT64, RFC 6052), `64:ff9b:1::/48` (Local NAT64, RFC 8215), `2002::/16` (6to4, RFC 3056), `100::/64` (Discard-Only, RFC 6666), `2001:2::/48` (Benchmarking, RFC 5180), and `2001:10::/28` (ORCHIDv2, RFC 7343) to `UNCONDITIONAL_BLOCKED_CIDRS`.
  - Added test cases in `IpRangeValidatorTest` verifying rejection of `::127.0.0.1`, `::169.254.169.254`, `64:ff9b::1`, `2002:7f00:1::1`, and `100::1`.

---

### P6-03 [MEDIUM] [VERIFIED BUG]: `URI.getHost()` Returning Null on Dotted-Hex and Short IPv4 Literals and Unstripped Trailing FQDN Root Dots
- **Issue:** Standard `java.net.URI.getHost()` returns `null` when parsed against dotted-hex (`http://0x7f.0.0.1:8080`) or short numeric IPv4 literals (`http://127.1`), because the authority label fails strict RFC 2396 host syntax, although `uri.getRawAuthority()` contains the raw host and port string. Additionally, trailing root DNS dots (`example.com.` or `127.0.0.1.`) were not stripped prior to scope and policy evaluation.
- **Impact:** Dotted-hex and short IP literals failed at step 4 ("Target URL does not specify a valid host") before reaching `ObfuscatedIpParser` at step 6, and trailing FQDN dots could lead to scope mismatches or DNS bypasses.
- **Remediation:**
  - In `PolicyEngine.evaluateUri()`, added raw authority fallback parsing when `uri.getHost()` is null: extracts the host portion and port from `uri.getRawAuthority()`, validating extracted ports against `ALLOWED_PORTS`.
  - Added trailing dot stripping in both `PolicyEngine.evaluateUri()` and `ObfuscatedIpParser.parse()` (`while (host.endsWith(".") && host.length() > 1) host = host.substring(0, host.length() - 1);`).
  - Added unit test cases in `PolicyEngineTest.obfuscatedIpLiterals()` for `http://0x7f.0.0.1:8080`, `http://127.1`, `https://example.com./api`, and `http://127.0.0.1./`.

---

### P6-04 [LOW] [VERIFIED INCONSISTENCY]: Missing RFC 9457 `invalidParams` in `PolicyEngine.enforce()` `PolicyViolationException`
- **Issue:** `PolicyEngine.enforce()` constructed `new PolicyViolationException("Policy violation: " + decision.reason())` with an empty `invalidParams` list, omitting field-level error attribution.
- **Impact:** Inconsistency with the RFC 9457 Problem Details specification in `docs/04-API-CONTRACTS.md` requiring `invalidParams` containing `name` and `reason`.
- **Remediation:**
  - Updated `PolicyEngine.enforce()` to populate `invalidParams` with `List.of(new InvalidParam("targetUrl", decision.reason()))`.
  - Added an assertion in `PolicyEngineTest.enforceMethod()` verifying that `getInvalidParams()` contains `targetUrl` and the policy denial rationale.

---

### P6-05 [LOW] [VERIFIED BUG]: 11-Second Live External Network DNS Timeout in `SystemDnsResolverTest`
- **Issue:** `SystemDnsResolverTest.resolveInvalidDomain()` resolved `"invalid.nonexistent.domain.xyz"`, triggering an external DNS lookup against upstream internet resolvers that stalled test execution for ~11 seconds until timing out.
- **Impact:** Excessive test suite latency and vulnerability to test flakiness in offline/air-gapped CI environments.
- **Remediation:**
  - Replaced `"invalid.nonexistent.domain.xyz"` with `"999.999.999.999"`, which `InetAddress.getAllByName()` recognizes immediately as an invalid address and rejects with `UnknownHostException` in `< 1ms` with zero network I/O.
  - Reduced total backend test execution time from ~56 seconds to ~30 seconds.

---

### P6-06 [MEDIUM] [VERIFIED BUG]: Truncation of Unbracketed IPv6 Target Hosts and Incomplete Bracket Stripping in `PolicyEngine.extractHost()` and `evaluateUri()`
- **Issue:** In `PolicyEngine.extractHost()`, the condition `if (colon > 0 && !trimmed.contains("]")) { trimmed = trimmed.substring(0, colon); }` truncated unbracketed IPv6 addresses (e.g. `"2606:2800:220:1:248:1893:25c8:1946"`) at the first colon to `"2606"`. Furthermore, `URI.getHost()` returned bracketed IPv6 strings without stripping surrounding brackets, causing scope mismatches when evaluated against unbracketed IPv6 ScopeAssets.
- **Impact:** IPv6 target evaluation failed scope matching against IPv6 ScopeAssets.
- **Remediation:**
  - In `PolicyEngine.extractHost()`, only strip `:port` when there is a single colon or when following a closing bracket (`]:port`), and strip surrounding `[` and `]` brackets from IPv6 literals.
  - In `PolicyEngine.evaluateUri()`, strip surrounding brackets from extracted authority host so `decision.targetHost()` and `isWithinScope()` consistently evaluate canonical unbracketed strings.
  - Added unit test in `PolicyEngineTest` verifying evaluation of `http://[2606:2800:220:1:248:1893:25c8:1946]:8080/api` against an unbracketed IPv6 `ScopeAsset`.

