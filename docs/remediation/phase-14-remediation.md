# Phase 14: Web Crawling & Asset Harvester Probes (`robots_txt`, `sitemap_xml`, `extract_links`, `extract_js_urls`) — Remediation Plan & Checklist

**Target:** Resolution of findings documented in `docs/audits/phase-14-audit.md`  
**Baseline Snapshot:** `docs/audits/snapshots/phase-14-snapshot.md`  

---

## Remediation Checklist

- [x] **P14-01 [HIGH] [SECURITY & RECON ACCURACY]**: Scheme filtering, host extraction hardening, and non-200 status code body parsing in `ExtractJsUrlsTool.java` and `ExtractLinksTool.java`:
  - Parse HTML whenever `!probeResult.bodyText().isBlank()` regardless of status code; report `statusCode` in `parsedData`.
  - Filter non-HTTP schemes (`javascript:`, `data:`, `blob:`, `mailto:`, `tel:`) in `ExtractJsUrlsTool`; require `http://` or `https://` with a non-empty host.
  - In `extractHost(String url)`, strip query (`?`) and fragment (`#`) delimiters prior to `URI.create`, strip surrounding `[` `]` and trailing root dots (`.`), and add authority fallback handling for malformed host components.
  - Reject explicit `null` and floating-point numbers for `maxLinks` in `ExtractLinksTool.validateParams`.
  - Added regression tests in `ExtractJsUrlsToolTest.java` (`ignoresNonHttpSchemesAndExtractsHostWithComplexQuery`, `parsesNon200ResponseWithBody`) and `ExtractLinksToolTest.java` (`validateParamsRejectsInvalidMaxLinks`, `parsesNon200ResponseBodyAndExtractsLinks`, `extractHostHandlesTrailingDotsAndComplexQuery`).
- [x] **P14-02 [MEDIUM] [FUNCTIONAL / RFC 3986 COMPLIANCE]**: Preserve query strings in relative URI resolution in `RobotsTxtTool.java` and `SitemapXmlTool.java`:
  - Replaced 7-argument `URI` constructor with RFC 3986 relative resolution: `baseUri.resolve("/robots.txt")` and `baseUri.resolve(customPath)`.
  - Reject explicit `null` and floating-point numbers for `customPath` and `maxUrls` in `SitemapXmlTool.validateParams` and `ToolCatalogRegistry.java`.
  - Added regression tests in `SitemapXmlToolTest.java` (`preservesQueryStringInCustomPathResolution`, `validateParamsRejectsInvalid`).
- [x] **P14-03 [MEDIUM] [FALSE POSITIVE REDUCTION / RECON ACCURACY]**: Enforce path-segment boundary matching for sensitive keywords in `RobotsTxtTool.java` and `SitemapXmlTool.java`:
  - Implemented `matchesSensitiveKeyword(String path, String keyword)` checking path segment start (`/`) and end delimiter (`/`, `?`, `#`, `.`, `-`, `_`, `*`, or end-of-string).
  - Synchronized `SENSITIVE_KEYWORDS` between tools to cover `/admin`, `/auth`, `/login`, `/api`, `/config`, `/backup`, `/db`, etc.
  - Added regression tests in `RobotsTxtToolTest.java` (`differentiatesSensitivePathsFromBenignPrefixMatches`) and `SitemapXmlToolTest.java` (`differentiatesSensitiveSitemapUrlsFromBenignPrefixMatches`).
- [x] **P14-04 [LOW] [TEST DETERMINISM & STABILITY]**: Disable background advisory thread generation in `ToolExecutionQueueAndFencingIT.java`:
  - Set `toolExecutionWorker.setAutoAdvisoryEnabled(false)` in both `setUp()` and `tearDown()` to eliminate background Ollama HTTP calls and prevent Surefire 30-second JVM exit hangs.
  - Verified clean JVM shutdown with 0 second exit delay across all 9 integration test scenarios.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 342/342 passed across all test suites (`.\mvnw.cmd test`):
  - `ExtractJsUrlsToolTest`: 3/3 passed.
  - `ExtractLinksToolTest`: 6/6 passed.
  - `RobotsTxtToolTest`: 4/4 passed.
  - `SitemapXmlToolTest`: 7/7 passed.
  - `HttpHeadersToolTest`: 10/10 passed.
  - `ToolExecutionQueueAndFencingIT`: 9/9 passed.
  - `ToolCatalogRegistryTest`: 11/11 passed.
  - `ToolCatalogControllerIT`: 2/2 passed.
  - `Rfc9525VerifierTest`: 6/6 passed.
  - `TlsInfoToolTest`: 5/5 passed.
  - `CookieParserTest`: 5/5 passed.
  - `DnsLookupToolTest`: 10/10 passed.
  - `WhoisLookupToolTest`: 9/9 passed.
  - `StandardWhoisQueryClientTest`: 8/8 passed.
  - `DnsjavaLookupClientTest`: 1/1 passed.
  - All existing backend tests passing.
- **Frontend Unit & Component Tests:** 116/116 passed across 11 test suites (`pnpm.cmd test:run`).
- **Frontend Production Build & Type-Check:** `vue-tsc --noEmit && vite build` succeeded with 0 TypeScript diagnostics or warnings.
- **Audit Snapshot:** Regenerated clean snapshot at `docs/audits/snapshots/phase-14-snapshot.md`.
