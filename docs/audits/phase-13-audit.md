# Phase 13: External Third-Party Reconnaissance Tools (`dns_lookup` & `whois_lookup`) — Architectural & Security Audit Report

**Date:** 2026-10-15  
**Audit Target:** `phase-13-snapshot.md` (`DnsLookupTool`, `WhoisLookupTool`, `DnsLookupClient`, `WhoisQueryClient`, `StandardWhoisQueryClient`, `DnsjavaLookupClient`, DNS & WHOIS wire protocols, SSRF referral guards, PII redaction, 32 KB payload bounds)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An adversarial security and architectural audit of Phase 13 identified 5 findings (1 High, 2 Medium, 2 Low) spanning RDAP redirect protocol validation, TLS hostname verification, HTTP redirect body skipping, chunked transfer encoding, special-purpose IPv6/IPv4 range detection, trailing dot normalization, multi-byte UTF-8 payload truncation, strict numeric parameter validation, and anchored regex matching for SPF/DMARC records. All 5 findings have been fully remediated and verified across 322 backend Maven tests (spanning unit, WireMock, and Testcontainers PostgreSQL integration suites with 83% JaCoCo instruction coverage) and 116 frontend Vitest tests, with clean type-checking and bundling (`vue-tsc --noEmit && vite build`).

---

## Detailed Findings & Remediations

### P13-01 [HIGH] [SECURITY / SSRF & PROTOCOL COMPLIANCE]: `StandardWhoisQueryClient.queryRdap` Redirect Scheme/Port Validation, TLS Hostname Verification & HTTP Body Framing
- **Issue:**
  - In `StandardWhoisQueryClient.java`, the initial RDAP endpoint implementation did not revalidate URL scheme or destination ports upon following HTTP `3xx` redirects. A malicious or compromised RDAP registry could redirect an audit probe to internal administrative ports (`http://victim:8080/` or `http://victim:22/`) or arbitrary non-HTTP schemes (`ftp://`, `file://`, `gopher://`).
  - Outbound TLS connections over `SSLSocket` did not configure endpoint identification algorithms (`params.setEndpointIdentificationAlgorithm("HTTPS")`), leaving HTTPS RDAP referral queries vulnerable to man-in-the-middle (MITM) spoofing.
  - When receiving `3xx` redirects or zero-length responses, `readHttpResponse` still attempted to read the response body under `PayloadLimitGuard`, risking socket read timeouts or payload decoding errors on empty/unframed redirect bodies. Furthermore, `Transfer-Encoding: chunked` responses from RDAP registries were parsed as raw bytes rather than being properly unframed.
- **Impact:** Potential SSRF port scanning via RDAP redirects, TLS hostname validation bypass, and failures when communicating with chunked RDAP servers.
- **Remediation:**
  - Extracted the configured RDAP port (`configuredRdapPort`) from `this.rdapBaseUrl` during client initialization.
  - In `queryRdap`, added strict validation on every hop:
    - Scheme must be strictly `http` or `https` (case-insensitive); otherwise throws `PolicyViolationException`.
    - Destination port must be `80`, `443`, or `configuredRdapPort` (permitting local WireMock test fixtures); otherwise throws `PolicyViolationException`.
  - Configured `params.setEndpointIdentificationAlgorithm("HTTPS")` on `SSLParameters` prior to socket handshake.
  - In `readHttpResponse`, immediately returned an empty body record when receiving `301`, `302`, `303`, `307`, `308`, `204`, `304`, or `Content-Length: 0`.
  - Implemented `readChunkedBody(InputStream in)` and `readLine(InputStream in)` to safely unframe chunked HTTP responses under the protection of `PayloadLimitGuard.wrap(in, PAYLOAD_CAP_BYTES, PAYLOAD_CAP_BYTES, false)`.
  - Added unit and WireMock regression tests in `StandardWhoisQueryClientTest` (`rdapRedirectDisallowedSchemeThrowsPolicyViolation`, `rdapRedirectDisallowedPortThrowsPolicyViolation`, `rdapParsesChunkedTransferEncoding`).

---

### P13-02 [MEDIUM] [SECURITY / SSRF & TARGET HANDLING]: Special-Purpose / Private IP Range Validation in `WhoisLookupTool` & Trailing Dot Normalization
- **Issue:**
  - `WhoisLookupTool.execute` previously evaluated local/private IP targets using only direct `InetAddress` methods (`isLoopbackAddress() || isSiteLocalAddress() || isLinkLocalAddress()`). This missed IPv6 Unique Local Addresses (`fc00::/7`, e.g. `fd00::1`), CGNAT (`100.64.0.0/10`), IPv4-mapped IPv6 loopbacks (`::ffff:127.0.0.1`), and other special-purpose ranges defined in RFC 6890.
  - Targets specified with trailing root dots (e.g. `http://localhost.:8080` or `https://example.com./`) bypassed domain name matching and caused DNS resolution queries to query malformed FQDNs like `_dmarc.example.com.`.
- **Impact:** Private/internal IP addresses in `LOCAL` mode could trigger unnecessary public WHOIS queries or fail unexpectedly instead of returning graceful `registered: false` outcomes.
- **Remediation:**
  - Injected `IpRangeValidator` into `WhoisLookupTool` (with backwards-compatible convenience constructor `public WhoisLookupTool(WhoisQueryClient whoisQueryClient, Clock clock)`).
  - Replaced the private IP check in `WhoisLookupTool.execute` with `boolean isPrivateOrSpecialIp = parsedIp != null && !ipRangeValidator.isAllowed(parsedIp, SessionMode.PUBLIC);`.
  - Updated `extractHost` in both `WhoisLookupTool` and `DnsLookupTool` to strip trailing root dots via `while (trimmed.endsWith(".") && trimmed.length() > 1) trimmed = trimmed.substring(0, trimmed.length() - 1);`.
  - Added regression tests in `WhoisLookupToolTest` (`executeHandlesLocalhostAndPrivateIpGracefully` with IPv6 ULA `[fd00::1]` and trailing dot `localhost.`) and `DnsLookupToolTest` (`executeNormalizesTrailingDotInTargetUrl`).

---

### P13-03 [MEDIUM] [DATA INTEGRITY / BUFFER OVERFLOW]: UTF-8 Byte Truncation via `Utf8StringUtils.truncateUtf8`
- **Issue:**
  - Both `WhoisLookupTool` and `DnsLookupTool` capped output using character-length slicing (`raw.substring(0, MAX_OUTPUT_BYTES)`).
  - Because multi-byte UTF-8 characters (e.g., Cyrillic registrar names, IDNs, emoji, international currency marks) require 2 to 4 bytes per code point, a 32,768-character string could consume up to 131,072 bytes on the wire, violating the strict 32 KB payload cap defined in `docs/05-TOOL-CATALOG.md`.
  - Character slicing also risked splitting surrogate pairs, creating malformed Unicode sequences.
- **Impact:** Violation of payload bounds in tool results and corrupted UTF-8 payloads.
- **Remediation:**
  - Replaced `substring(0, MAX_OUTPUT_BYTES)` with `Utf8StringUtils.truncateUtf8(raw, MAX_OUTPUT_BYTES)` in both `WhoisLookupTool.execute` and `DnsLookupTool.buildRawOutput`.
  - Added regression tests in `WhoisLookupToolTest` (`executeTruncatesMultiByteUtf8To32Kb`) and `DnsLookupToolTest` (`executeTruncatesMultiByteUtf8To32Kb`) verifying that multi-byte strings are truncated to $\le 32,768$ bytes without broken code points.

---

### P13-04 [LOW] [INPUT VALIDATION]: Strict Integer Validation for `referralDepth` Parameter
- **Issue:**
  - In `WhoisLookupTool.validateParams`, the parameter check used loose `Number.intValue()`, allowing floating-point values like `1.5` or 64-bit overflow values like `4294967297L` (which cast to `1`) to pass validation.
- **Impact:** Inconsistent input validation semantics and unexpected referral recursion behaviors.
- **Remediation:**
  - Implemented `parseStrictInt(Object raw)` in `WhoisLookupTool`, requiring inputs to be strict integer types (`Byte`, `Short`, `Integer`), in-range `Long`, or valid numeric `String` parseable without overflow.
  - Non-integral numbers (Float, Double) and out-of-range values throw `ValidationException`.
  - Added unit regression tests in `WhoisLookupToolTest.validateParamsRejectsInvalidDepth` asserting rejection of `1.5` and `4294967297L`.

---

### P13-05 [LOW] [FALSE POSITIVE REDUCTION]: Anchored SPF and DMARC Regular Expression Matching
- **Issue:**
  - In `DnsLookupTool.java`, SPF and DMARC presence checks used substring contains (`lower.startsWith("v=spf1") || lower.contains("v=spf1")`).
  - Unrelated TXT commentary or documentation records (such as `"doc note: see v=spf1 specification for guidance"` or `"policy note: refer to v=dmarc1 documentation"`) triggered false positive matches, falsely marking SPF or DMARC as present.
- **Impact:** Inaccurate security observations and false sense of security regarding domain email authentication policies.
- **Remediation:**
  - Defined strict, anchored regex patterns adhering to RFC 7208 and RFC 7489:
    - `SPF_RECORD_PATTERN = Pattern.compile("(?i)^\\s*v=spf1(?:\\s|$).*")`
    - `DMARC_RECORD_PATTERN = Pattern.compile("(?i)^\\s*v=dmarc1(?:\\s*;.*|\\s*$)")`
  - Replaced substring matching in `DnsLookupTool.execute` with `SPF_RECORD_PATTERN.matcher(txt).matches()` and `DMARC_RECORD_PATTERN.matcher(txt).matches()`.
  - Added unit regression test in `DnsLookupToolTest` (`executeAvoidsFalsePositiveOnCommentaryTxtRecords`) verifying that documentation TXT records do not trigger false positives and missing SPF/DMARC observations are properly generated.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 322/322 passed across all test suites (`mvnw.cmd test`):
  - `StandardWhoisQueryClientTest`: 8/8 passed (WireMock RDAP JSON parsing, PII redaction, port 43 referral chain, loop cycle prevention, redirect scheme/port validation, and chunked transfer encoding).
  - `WhoisLookupToolTest`: 9/9 passed (parameter validation, days-until-expiry calculation, lifecycle observations, transfer lock detection, IPv6 ULA / localhost graceful handling, 32 KB UTF-8 truncation, and strict integer parsing).
  - `DnsLookupToolTest`: 10/10 passed (record querying, anchored SPF/DMARC matching, commentary record discrimination, permissive SPF observations, localhost handling, trailing dot normalization, and 32 KB UTF-8 truncation).
  - `DnsjavaLookupClientTest`: 1/1 passed.
  - `ToolCatalogRegistryTest`: 11/11 passed (including referralDepth 0..3 validation).
  - `ToolCatalogControllerIT`: 2/2 passed.
  - All 281 existing backend tests passing.
  - **Code Coverage:** JaCoCo instruction coverage measured at **83%** (15,408 of 18,555 instructions covered, meeting the $\ge 80\%$ project gate).
- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm test:run`).
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-13-snapshot.md`.
