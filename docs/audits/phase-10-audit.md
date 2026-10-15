# Phase 10: Core HTTP & TLS Direct Probes (`http_headers` and `tls_info`) — Architectural & Security Audit Report

**Date:** 2026-10-15  
**Audit Target:** `phase-10-snapshot.md` (Core HTTP & TLS Direct Target Probes, IP-Pinned HTTP Transport, Cookie Parser, and RFC 9525 / RFC 6066 SNI/SAN Verifier)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An architectural, transport, and security audit of the Phase 10 implementation identified 4 findings (2 High, 2 Medium) spanning synthetic test overrides that masked observation heuristics in `TlsInfoToolTest`, socket transport stream handling failures with gzip decompression on empty bodies / redirects / chunked responses in `PinnedHttpClient`, redundant DNS resolution opening TOCTOU rebinding windows in `HttpHeadersTool` and `TlsInfoTool`, and numeric port parsing / IPv6 bracket formatting edge cases. All 4 findings have been thoroughly verified, remediated, and validated across 264 automated tests with all JaCoCo coverage thresholds met (>= 80%).

---

## Detailed Findings & Remediations

### P10-01 [HIGH] [VERIFIED BUG]: Fake Test Override in `TlsInfoToolTest.observationHeuristicsCoverage()`
- **Issue:**
  1. In `TlsInfoToolTest.java`, `observationHeuristicsCoverage()` instantiated an anonymous subclass of `TlsInfoTool` that completely overrode `execute()`, testing copy-pasted `if` statements inside the test method rather than invoking `TlsInfoTool.extractObservations()`.
  2. The `0 <= daysUntilExpiry <= 30` ("expiring soon") heuristic branch was omitted and left untested.
- **Impact:** Production observation generation logic was masked by synthetic test code; actual observation heuristics were not tested against real `TlsInfoTool` methods, creating false confidence and risking undetected regressions.
- **Remediation:**
  - Changed `extractObservations(...)` and `buildRawOutput(...)` in `TlsInfoTool.java` from `private` to package-private for direct testability without external package leakage.
  - Rewrote `TlsInfoToolTest.observationHeuristicsCoverage()` to call the real `tool.extractObservations(...)` method directly.
  - Verified all 6 heuristics plus clean modern handshake:
    1. Deprecated protocol (`TLSv1`, `TLSv1.1`, `SSLv3`) -> `HIGH` (`TLS_PROTOCOL`)
    2. Weak cipher (`TLS_RSA_WITH_3DES_EDE_CBC_SHA`, `RC4`) -> `HIGH` (`TLS_CIPHER`)
    3. Expired certificate (`daysUntilExpiry = -15`) -> `HIGH` (`TLS_CERTIFICATE`)
    4. Expiring-soon certificate (`daysUntilExpiry = 14`) -> `MEDIUM` (`TLS_CERTIFICATE`)
    5. Self-signed certificate (`selfSigned = true`) -> `MEDIUM` (`TLS_CERTIFICATE`)
    6. Hostname mismatch (`hostnameVerified = false`) -> `HIGH` (`TLS_CERTIFICATE`)
    7. Clean modern handshake (`TLSv1.3`, `TLS_AES_256_GCM_SHA384`, `daysUntilExpiry = 90`, `selfSigned = false`, `hostnameVerified = true`) -> `0` observations.

---

### P10-02 [HIGH] [VERIFIED BUG]: `GZIPInputStream` Premature EOF / `ZipException` on Empty Bodies, Redirects, and `Transfer-Encoding: chunked` in `PinnedHttpClient`
- **Issue:**
  1. In `PinnedHttpClient.parseHttpResponse()`, the raw socket input stream was unconditionally wrapped in `PayloadLimitGuard.wrap(in, isGzip)` (`GZIPInputStream`) even when status codes had no body (`1xx`, `204`, `304`, redirects `301/302/303/307/308`) or when `Content-Length: 0`. Java's `GZIPInputStream` constructor immediately reads a 10-byte header, causing an `EOFException` on empty streams.
  2. If a server responded with `Transfer-Encoding: chunked` and `Content-Encoding: gzip`, raw chunk hex lengths preceded the gzip magic bytes on the socket stream, causing `ZipException: Not in GZIP format`.
  3. Responses with positive `Content-Length` on persistent connections could block waiting for socket close.
- **Impact:** HTTP header probes failed with unhandled `EOFException` or `ZipException` whenever probing servers sending gzip headers with redirects, chunked responses, or zero content length.
- **Remediation:**
  - In `PinnedHttpClient.parseHttpResponse()`:
    - Identified responses without a body (`1xx`, `204`, `304`, redirects `301, 302, 303, 307, 308`, or `Content-Length: 0`) and skipped reading the response body, returning empty `bodyBytes`.
    - Implemented static inner class `ChunkedInputStream` to de-chunk HTTP/1.1 chunked streams before passing to `PayloadLimitGuard.wrap(...)` / `GZIPInputStream`, enforcing Tier 1 wire byte limits.
    - Implemented static inner class `FixedLengthInputStream` for bounded positive `Content-Length` reads so connections do not hang waiting for socket close.
    - Caught and gracefully handled `EOFException` and `ZipException` on empty or truncated gzip streams.
  - Added comprehensive unit tests in `HttpHeadersToolTest`:
    - `gzipCompressedResponse()` (200 OK with `Content-Encoding: gzip`).
    - `chunkedGzipCompressedResponse()` (200 OK with `Transfer-Encoding: chunked` and `Content-Encoding: gzip` over a live loopback socket).
    - `gzipRedirectWithZeroContentLength()` (302 Found redirect with `Content-Encoding: gzip` and `Content-Length: 0`).

---

### P10-03 [MEDIUM] [VERIFIED BUG]: Redundant DNS Re-Resolution in `TlsInfoTool` and `HttpHeadersTool` Bypassing Context Policy IP Pinning
- **Issue:**
  - `ToolExecutionWorker` performs pre-flight `PolicyEngine.evaluate()` and passes the approved `PolicyDecision` (with pinned `resolvedIp`) in `context.policyDecision()`.
  - However, `TlsInfoTool.execute()` ignored `context.policyDecision()` and called `policyEngine.evaluate()` a second time, and `HttpHeadersTool.execute()` called `policyEngine.evaluate()` a second time when `customPort` was provided.
  - Invoking `policyEngine.evaluate()` again triggered `DnsResolver.resolveAll()` a second time, opening a TOCTOU DNS rebinding window where an attacker-controlled DNS server could return a public IP during pre-flight and a private/internal IP during tool execution.
- **Impact:** Weakened SSRF protection and TOCTOU DNS rebinding vulnerability during direct target probe executions.
- **Remediation:**
  - In both `HttpHeadersTool.execute()` and `TlsInfoTool.execute()`:
    - Checked `if (context.policyDecision() != null && context.policyDecision().allowed() && context.policyDecision().resolvedIp() != null)`.
    - Validated target port against `PolicyEngine.ALLOWED_PORTS` (throwing `PolicyViolationException` if disallowed), and directly reused `context.policyDecision().resolvedIp()` without calling `policyEngine.evaluate()` or resolving DNS again.
    - Only invoked `policyEngine.evaluate()` when `context.policyDecision()` is null.
  - Added unit tests in both `HttpHeadersToolTest` (`reusesPreResolvedIpWithoutDnsResolution`) and `TlsInfoToolTest` (`reusesPreResolvedIpWithoutDnsResolution`) with counting DNS resolvers asserting `dnsCallCount.get() == 0`.

---

### P10-04 [MEDIUM] [VERIFIED BUG]: Numeric Port Parsing Rejection and IPv6 Host Extraction/Formatting Edge Cases
- **Issue:**
  - In `TlsInfoTool` and `HttpHeadersTool`, `parsePort()` used `((Number) val).intValue()` without validating against floating-point types (`Double`/`Float`) or integer overflow from `Long`, and did not validate port range `1..65535` when port was supplied as a `String`.
  - Naive `indexOf(':')` in host extraction broke on unbracketed IPv6 addresses (e.g., `2001:db8::1`), erroneously truncating them to `2001` or misparsing colons as port delimiters.
  - HTTP `Host` header formatting in `PinnedHttpClient` and probe URL construction in `TlsInfoTool` failed to enclose IPv6 literals in brackets `[...]`.
- **Impact:** Malformed or floating-point ports could bypass validation; probing IPv6 targets resulted in malformed HTTP requests and connection failures.
- **Remediation:**
  - In `parsePort()` across both tools: rejected `Float` and `Double` instances; strictly checked range `1 <= port <= 65535` for `Long`, `Integer`, and parsed `String`.
  - Fixed `extractHost(...)` and `extractHostFromAuthority(...)` to recognize bracketed `[...]` IPv6 addresses and ensure multiple colons in raw IPv6 addresses are not mistaken for port delimiters.
  - Formatted IPv6 addresses with brackets (`[<host>]`) when constructing HTTP `Host` headers in `PinnedHttpClient` and probe URLs in `TlsInfoTool`.
  - Added test coverage in `HttpHeadersToolTest` and `TlsInfoToolTest` verifying port validation and IP/host parsing.
