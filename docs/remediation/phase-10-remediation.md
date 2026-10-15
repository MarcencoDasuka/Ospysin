# Phase 10: Core HTTP & TLS Direct Probes (`http_headers` and `tls_info`) — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-10-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-10-snapshot.md`  

---

## Remediation Checklist

- [x] **P10-01 [HIGH] [VERIFIED BUG]**: Eliminate fake test override in `TlsInfoToolTest.observationHeuristicsCoverage()` by changing `extractObservations(...)` and `buildRawOutput(...)` to package-private in `TlsInfoTool.java`, invoking `tool.extractObservations(...)` directly on the real production tool, and verifying all 6 heuristics (deprecated protocol, weak cipher, expired certificate, expiring-soon certificate, self-signed certificate, hostname mismatch) plus clean modern handshake.
- [x] **P10-02 [HIGH] [VERIFIED BUG]**: Prevent premature `EOFException` and `ZipException` in `PinnedHttpClient.parseHttpResponse()` by skipping body reads on `1xx`, `204`, `304`, redirects (`301, 302, 303, 307, 308`), or `Content-Length: 0`, implementing `ChunkedInputStream` to de-chunk HTTP/1.1 chunked streams before gzip decompression, implementing `FixedLengthInputStream` for bounded positive `Content-Length` reads, gracefully catching `EOFException`/`ZipException`, and adding unit tests for gzip responses, chunked gzip streams, and gzip redirect responses.
- [x] **P10-03 [MEDIUM] [VERIFIED BUG]**: Eliminate TOCTOU DNS rebinding window by reusing `context.policyDecision().resolvedIp()` in `HttpHeadersTool.execute()` and `TlsInfoTool.execute()` without redundant DNS lookup, validating target ports against `PolicyEngine.ALLOWED_PORTS`, and adding unit tests asserting that DNS resolver calls equal 0 when pre-flight policy decision is present.
- [x] **P10-04 [MEDIUM] [VERIFIED BUG]**: Harden numeric port parsing and IPv6 host extraction/formatting by rejecting `Float`/`Double` and enforcing `1..65535` range across `Long`, `Integer`, and `String`, preserving bracketed/unbracketed IPv6 addresses in `extractHost(...)` and `extractHostFromAuthority(...)`, and enclosing IPv6 addresses in brackets `[<host>]` in HTTP `Host` headers and TLS probe URLs.

---

## Verification Summary

- **Targeted Probe Tests Executed:** 26/26 passed (`mvnw.cmd test "-Dtest=CookieParserTest,Rfc9525VerifierTest,HttpHeadersToolTest,TlsInfoToolTest"`):
  - `CookieParserTest`: 5/5 passed (standard cookie, secure flags, SameSite case insensitivity, path/domain extraction, multiple attributes).
  - `HttpHeadersToolTest`: 10/10 passed (validateParams port rejection/acceptance, header capture, observation generation, safe redirect following, malicious redirect blocking in public mode, hop limit enforcement, gzip compressed response, chunked gzip response, 302 gzip redirect with Content-Length 0, pre-resolved IP reuse without DNS resolution).
  - `Rfc9525VerifierTest`: 6/6 passed (CN matching, SAN dNSName matching, wildcard matching, SAN IP matching, hostname mismatch rejection, null/empty safety).
  - `TlsInfoToolTest`: 5/5 passed (validateParams, observation heuristics on all 6 conditions + modern handshake, pre-resolved IP reuse without DNS resolution, disallowed port policy violation, port range validation).
- **Full Backend Build & Integration Suite:** 264/264 passed across all suites (`mvnw.cmd clean verify`):
  - 100% of tests passed with 0 failures, 0 errors, and 0 skipped.
  - Total verify execution time: 55.560 s.
- **Code Coverage:** JaCoCo analyzed bundle `ospysin-backend` with 98 classes. All coverage checks have been met (instruction coverage >= 80% project gate).
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-10-snapshot.md`.
