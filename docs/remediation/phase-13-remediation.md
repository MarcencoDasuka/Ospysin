# Phase 13: External Third-Party Reconnaissance Tools (`dns_lookup` & `whois_lookup`) — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-13-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-13-snapshot.md`  

---

## Remediation Checklist

- [x] **P13-01 [HIGH] [SECURITY / SSRF & PROTOCOL COMPLIANCE]**: Harden RDAP redirect validation, TLS hostname verification, and HTTP body framing in `StandardWhoisQueryClient.java`:
  - Validate scheme (`http`/`https` only) and port (`80`, `443`, or `configuredRdapPort`) on every redirect hop, throwing `PolicyViolationException` on violation.
  - Set `params.setEndpointIdentificationAlgorithm("HTTPS")` on `SSLSocket` parameters before handshake to ensure peer certificate verification matches RDAP host.
  - Skip reading body on redirect and empty responses (`301`, `302`, `303`, `307`, `308`, `204`, `304`, `Content-Length: 0`).
  - Decode `Transfer-Encoding: chunked` streams safely under `PayloadLimitGuard.wrap(in, PAYLOAD_CAP_BYTES, PAYLOAD_CAP_BYTES, false)`.
  - Added WireMock regression tests `rdapRedirectDisallowedSchemeThrowsPolicyViolation`, `rdapRedirectDisallowedPortThrowsPolicyViolation`, and `rdapParsesChunkedTransferEncoding` in `StandardWhoisQueryClientTest.java`.
- [x] **P13-02 [MEDIUM] [SECURITY / SSRF & TARGET HANDLING]**: Enforce comprehensive special-purpose IP range validation in `WhoisLookupTool.java` and strip trailing dots in `extractHost`:
  - Injected `IpRangeValidator` into `WhoisLookupTool` with backwards-compatible constructor `WhoisLookupTool(WhoisQueryClient, Clock)`.
  - Check `!ipRangeValidator.isAllowed(parsedIp, SessionMode.PUBLIC)` to cover IPv6 ULA (`fc00::/7`), CGNAT (`100.64.0.0/10`), IPv4-mapped loopbacks (`::ffff:127.0.0.1`), and RFC 1918 private subnets for graceful `registered: false` handling.
  - Strip trailing FQDN root dots via `while (trimmed.endsWith(".") && trimmed.length() > 1) trimmed = trimmed.substring(0, trimmed.length() - 1);` in both `WhoisLookupTool.extractHost` and `DnsLookupTool.extractHost`.
  - Added regression tests in `WhoisLookupToolTest.java` (IPv6 ULA `[fd00::1]` and trailing-dot `localhost.`) and `DnsLookupToolTest.java` (trailing-dot FQDN normalization).
- [x] **P13-03 [MEDIUM] [DATA INTEGRITY / BUFFER OVERFLOW]**: Enforce 32 KB payload bounds using UTF-8 byte boundary truncation:
  - Replaced character-length slicing with `Utf8StringUtils.truncateUtf8(raw, MAX_OUTPUT_BYTES)` in both `WhoisLookupTool.java` and `DnsLookupTool.java`.
  - Added regression tests in `WhoisLookupToolTest.java` and `DnsLookupToolTest.java` asserting multi-byte UTF-8 string truncation to $\le 32,768$ bytes without broken Unicode code points.
- [x] **P13-04 [LOW] [INPUT VALIDATION]**: Enforce strict integer parsing for `referralDepth` parameter:
  - Implemented `parseStrictInt(Object raw)` in `WhoisLookupTool.java` rejecting non-integral numbers (Float, Double), 64-bit overflow values, and malformed strings with `ValidationException`.
  - Added regression tests in `WhoisLookupToolTest.java` asserting rejection of `1.5` and `4294967297L`.
- [x] **P13-05 [LOW] [FALSE POSITIVE REDUCTION]**: Anchor SPF and DMARC regular expressions in `DnsLookupTool.java`:
  - Replaced substring matching with anchored patterns `SPF_RECORD_PATTERN = Pattern.compile("(?i)^\\s*v=spf1(?:\\s|$).*")` and `DMARC_RECORD_PATTERN = Pattern.compile("(?i)^\\s*v=dmarc1(?:\\s*;.*|\\s*$)")`.
  - Added regression test in `DnsLookupToolTest.java` verifying that commentary/documentation TXT records (e.g. `"doc note: see v=spf1..."`) do not trigger false positive matches.

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
- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm test:run`):
  - `SessionWorkspaceView.spec.ts`: 23/23 passed.
  - `workspace.store.spec.ts`: 11/11 passed.
  - `http.spec.ts`: 16/16 passed.
  - `sessions.store.spec.ts`: 15/15 passed.
  - `NewSessionModal.spec.ts`: 11/11 passed.
  - `HomeView.spec.ts`: 8/8 passed.
  - `LoginView.spec.ts`: 9/9 passed.
  - `auth.store.spec.ts`: 11/11 passed.
  - `AppHeader.spec.ts`: 4/4 passed.
  - `health.store.spec.ts`: 4/4 passed.
  - `router.spec.ts`: 4/4 passed.
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-13-snapshot.md`.
