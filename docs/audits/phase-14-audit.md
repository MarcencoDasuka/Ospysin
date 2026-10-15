# Phase 14: Web Crawling & Asset Harvester Probes (`robots_txt`, `sitemap_xml`, `extract_links`, `extract_js_urls`) — Architectural & Security Audit Report

**Date:** 2026-10-15  
**Audit Target:** `phase-14-snapshot.md` (`RobotsTxtTool`, `SitemapXmlTool`, `ExtractLinksTool`, `ExtractJsUrlsTool`, `PinnedHttpClient`, `PinnedProbeResult`, `ToolCatalogRegistry`, body-capturing bounded streams, XXE defenses, Jsoup DOM harvesting)  
**Status:** VERIFIED / REMEDIATED  

---

## Executive Summary

An adversarial security and architectural audit of Phase 14 identified 4 findings (1 High, 2 Medium, 1 Low) spanning non-HTTP script scheme filtering, host extraction hardening, non-200 status code body parsing, relative URI resolution with query parameter preservation, path-segment boundary matching for sensitive keyword detection, and background thread cleanup in integration test harnesses. All 4 findings have been fully remediated and verified across **342 backend Maven tests** (spanning unit, WireMock, and Testcontainers PostgreSQL integration suites) and **116 frontend Vitest tests**, with clean type-checking and bundling (`vue-tsc --noEmit && vite build`).

---

## Detailed Findings & Remediations

### P14-01 [HIGH] [SECURITY & RECON ACCURACY]: Scheme Filtering, Host Extraction Hardening, and Non-200 Status Body Parsing in `ExtractJsUrlsTool` & `ExtractLinksTool`
- **Issue:**
  - `ExtractJsUrlsTool` and `ExtractLinksTool` previously skipped HTML parsing whenever `finalStatusCode != 200`. Error or authentication challenge pages (HTTP 401 Unauthorized, 403 Forbidden, 404 Not Found, 500) frequently contain script tags, login widgets, and internal API routes of high reconnaissance value.
  - `ExtractJsUrlsTool` did not filter non-HTTP script schemes (`javascript:`, `data:`, `blob:`, `mailto:`, `tel:`), potentially treating them as external scripts and emitting false-positive Subresource Integrity (SRI) security observations.
  - `extractHost` in both tools called `URI.create` directly on raw URLs without stripping query strings or fragments. Query strings containing characters like pipe `|` (e.g. `bundle.js?v=1|2`) triggered RFC 2396 `IllegalArgumentException` inside `URI.create`, causing valid script URLs and links to be dropped.
  - Targets and links specified with trailing FQDN root dots (e.g. `example.com.`) or authority strings with port numbers without explicit host parsing failed equality comparisons against canonical target hosts.
- **Impact:** Missed reconnaissance findings on non-200 pages, false-positive SRI alerts on non-HTTP pseudo-schemes, parsing exceptions on complex query strings, and inaccurate internal/external link segregation.
- **Remediation:**
  - Modified both `ExtractJsUrlsTool` and `ExtractLinksTool` to parse HTML whenever `!probeResult.bodyText().isBlank()`, irrespective of HTTP status code, and exposed `statusCode` in `parsedData`.
  - In `ExtractJsUrlsTool`, filtered out non-HTTP schemes (`javascript:`, `data:`, `blob:`, `mailto:`, `tel:`) and enforced that scripts start with `http://` or `https://` with a non-empty host before adding to scripts or evaluating SRI.
  - In both tools, hardened `extractHost(String url)`: stripped query (`?`) and fragment (`#`) delimiters prior to `URI.create`, stripped surrounding brackets `[` `]` on IPv6 addresses, stripped trailing root dots (`.`), and added authority fallback parsing for unconventional authorities.
  - In `ExtractLinksTool.validateParams`, rejected explicit `null` for `maxLinks` and disallowed non-integral floating-point numbers in `parseInteger`.
  - Added comprehensive regression tests in `ExtractJsUrlsToolTest` (`ignoresNonHttpSchemesAndExtractsHostWithComplexQuery`, `parsesNon200ResponseWithBody`) and `ExtractLinksToolTest` (`validateParamsRejectsInvalidMaxLinks`, `parsesNon200ResponseBodyAndExtractsLinks`, `extractHostHandlesTrailingDotsAndComplexQuery`).

---

### P14-02 [MEDIUM] [FUNCTIONAL / RFC 3986 COMPLIANCE]: URI Resolution & Query Parameter Preservation in `RobotsTxtTool` & `SitemapXmlTool`
- **Issue:**
  - `RobotsTxtTool` and `SitemapXmlTool` previously constructed target URIs using the 7-argument constructor `new URI(baseUri.getScheme(), baseUri.getUserInfo(), baseUri.getHost(), baseUri.getPort(), path, null, null)`.
  - Passing a `customPath` containing query parameters (e.g., `/sitemap.xml?type=posts&page=1` or `/sitemaps/index.php?format=xml`) to the 7-argument `URI` constructor caused the question mark `?` to be percent-encoded as `%3F` in the path component, converting the query into an invalid resource path `/sitemap.xml%3Ftype=posts&page=1` and breaking sitemap retrieval on query-driven CMSs.
- **Impact:** Malformed requests to query-driven sitemap URLs and HTTP 404 responses from target servers.
- **Remediation:**
  - Replaced the 7-argument constructor with standard RFC 3986 relative resolution: `baseUri.resolve("/robots.txt")` in `RobotsTxtTool` and `baseUri.resolve(customPath)` in `SitemapXmlTool`.
  - In `SitemapXmlTool.validateParams`, rejected explicit `null` for `customPath` and `maxUrls`, and disallowed floating-point numbers in `parseInteger`.
  - In `ToolCatalogRegistry`, updated parameter validation to reject explicit `null` values for `customPath`, `maxUrls`, and `maxLinks`.
  - Added regression tests in `SitemapXmlToolTest` (`preservesQueryStringInCustomPathResolution`, `validateParamsRejectsInvalid`) and `RobotsTxtToolTest`.

---

### P14-03 [MEDIUM] [FALSE POSITIVE REDUCTION / RECON ACCURACY]: Path-Segment Boundary Matching for Sensitive Keywords in `RobotsTxtTool` & `SitemapXmlTool`
- **Issue:**
  - Both tools previously used naive substring matching (`path.contains(keyword)`) against a list of sensitive prefixes (e.g. `/admin`, `/auth`, `/api`, `/config`, `/db`).
  - This generated false-positive sensitive path observations for completely benign content that shared a prefix with sensitive keywords, such as `/author/john-doe` (matching `/auth`), `/apiculture` (matching `/api`), `/configuration-guide` (matching `/config`), and `/dba-blog` or `/database-tutorial` (matching `/db`).
- **Impact:** Erroneous security observations and degraded signal-to-noise ratio in reconnaissance reports.
- **Remediation:**
  - Implemented `matchesSensitiveKeyword(String path, String keyword)` in both `RobotsTxtTool` and `SitemapXmlTool`.
  - Stripped query (`?`) and fragment (`#`) delimiters from the evaluated path.
  - Required matching occurrences to start at a path segment boundary (`idx == 0 || path.charAt(idx - 1) == '/'`).
  - Required matching occurrences to end either at the path end (`endIdx == path.length()`) or at a boundary delimiter (`'/'`, `'?'`, `'#'`, `'.'`, `'-'`, `'_'`, `'*'`).
  - Synchronized `SENSITIVE_KEYWORDS` between tools to cover `/admin`, `/auth`, `/login`, `/api`, `/config`, `/backup`, `/db`, etc.
  - Added regression tests in `RobotsTxtToolTest` (`differentiatesSensitivePathsFromBenignPrefixMatches`) and `SitemapXmlToolTest` (`differentiatesSensitiveSitemapUrlsFromBenignPrefixMatches`) verifying that benign words are excluded while true sensitive endpoints are flagged.

---

### P14-04 [LOW] [TEST DETERMINISM & STABILITY]: Background LLM Advisory Thread Leaks in `ToolExecutionQueueAndFencingIT`
- **Issue:**
  - In `ToolExecutionQueueAndFencingIT.java`, asynchronous tool executions triggered background `LlmAdvisoryService` advisory generation tasks via `ToolExecutionWorker`.
  - In test environments lacking a local Ollama container or model endpoint, these background advisory threads continuously attempted connections with socket read timeouts, outliving test execution and causing Surefire to hang on JVM shutdown: `[ERROR] Surefire is going to kill self fork JVM. The exit has elapsed 30 seconds after System.exit(0)`.
- **Impact:** 30-second delays in test runs and non-deterministic build pipeline exit status.
- **Remediation:**
  - Added `toolExecutionWorker.setAutoAdvisoryEnabled(false)` to both `@BeforeEach setUp()` and `@AfterEach tearDown()` in `ToolExecutionQueueAndFencingIT.java`.
  - Completely eliminated background advisory thread spawning during queue and fencing integration tests.
  - Verified clean JVM shutdown with 0 second exit delay and 0 Surefire timeout warnings.

---

## Verification Summary

- **Backend Test Suite (Unit & Integration):** 342/342 passed across all test suites (`.\mvnw.cmd test`):
  - `ExtractJsUrlsToolTest`: 3/3 passed (script cataloging, SRI verification, inline API endpoint extraction, non-HTTP scheme filtering, and non-200 body parsing).
  - `ExtractLinksToolTest`: 6/6 passed (internal/external link segregation, insecure HTTP form submission on HTTPS target, parameter validation, non-200 body parsing, and trailing dot / complex query host extraction).
  - `RobotsTxtToolTest`: 4/4 passed (valid robots.txt parsing, soft-404 HTML handling, 404 Not Found handling, and path-segment boundary sensitive keyword matching).
  - `SitemapXmlToolTest`: 7/7 passed (urlset parsing, sitemap index parsing, XXE injection rejection, query string preservation in customPath, parameter validation, and benign prefix differentiation).
  - `HttpHeadersToolTest`: 10/10 passed.
  - `ToolExecutionQueueAndFencingIT`: 9/9 passed (asynchronous lifecycle, epoch fencing, worker lease expiration, watchdog reclamation, clean shutdown without hang).
  - `ToolCatalogRegistryTest`: 11/11 passed (null and boundary rejection across all registered tools).
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
