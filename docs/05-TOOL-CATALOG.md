# 05. Tool Catalog Specification

## Overview
This catalog defines the 15 reconnaissance, vulnerability assessment, and exploit surface discovery tools available in version 1 of Ospysin. All tools are designed for **proactive self-defense**, enabling operators to audit their own web applications and infrastructure. Tools execute non-destructively to uncover active vulnerabilities, leaked credentials, configuration flaws, and exploitable surfaces before adversaries can abuse them.

---

## Canonical 3-Tier Tool Taxonomy

The 15 registered tools are organized into three canonical operational tiers based on their network interaction model (`executionType` enum):

```text
+----------------------------------------------------------------------------------------------------+
| 1. External Third-Party Recon [executionType: THIRD_PARTY_RECON] (2 tools)                         |
|    - Queries external registries and third-party DNS infrastructure (no direct target server I/O)  |
|    - dns_lookup, whois_lookup                                                                      |
+----------------------------------------------------------------------------------------------------+
| 2. Active Direct Target Probes [executionType: DIRECT_TARGET_PROBE] (11 tools)                      |
|    - Directly connects to the target host/port via TCP/TLS socket or HTTP request                  |
|    - tls_info, http_headers, robots_txt, sitemap_xml, extract_links, extract_js_urls, tech_detect,  |
|      sensitive_files_check, js_secrets_scanner, cors_misconfig_check, subdomain_takeover_check     |
+----------------------------------------------------------------------------------------------------+
| 3. Offline Analytical Tools [executionType: OFFLINE_ANALYSIS] (2 tools)                            |
|    - Executes purely local computation over evidence collected in preceding steps (0 network I/O) |
|    - security_headers_score, cve_matcher                                                           |
+----------------------------------------------------------------------------------------------------+
```

### Four-Tier Payload Boundaries

All tool executions adhere to four distinct payload thresholds to prevent memory exhaustion, decompression bombs, and database bloat:

1. **Tier 1 (Wire Bytes)**: 1 MB hard limit on raw socket bytes read from the network per response.
2. **Tier 2 (Decompressed Bytes)**: 2 MB maximum decompressed stream size. Decompression bomb ratio protection triggers when decompressed bytes $D > 100 \text{ KB}$: if $\frac{D}{C} > 10$, the stream is immediately terminated.
3. **Tier 3 (Aggregate Multi-Asset Cap)**: 5 MB cumulative limit across all fetched assets in multi-request tools (e.g., `js_secrets_scanner` scanning up to 10 JS bundles).
4. **Tier 4 (Persisted Row Storage)**: 1 MB maximum size for `tool_results.raw_output` database column. Larger analytical datasets are summarized or capped prior to database persistence.

---

## Catalog Summary

| ID | Name | Execution Type (`executionType`) | Risk | Timeout | Wire Cap | Decompressed Cap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **External Third-Party Recon** | | | | | | |
| `dns_lookup` | DNS Record Enumeration | `THIRD_PARTY_RECON` | LOW | 10s | 32 KB | 32 KB |
| `whois_lookup` | WHOIS / RDAP Registration | `THIRD_PARTY_RECON` | LOW | 15s | 32 KB | 32 KB |
| **Active Direct Target Probes** | | | | | | |
| `tls_info` | TLS/SSL Handshake & Cipher Suite | `DIRECT_TARGET_PROBE` | LOW | 10s | 64 KB | 64 KB |
| `http_headers` | HTTP Headers & Cookies | `DIRECT_TARGET_PROBE` | LOW | 10s | 64 KB | 64 KB |
| `robots_txt` | Robots.txt Disallow Inspection | `DIRECT_TARGET_PROBE` | LOW | 10s | 128 KB | 128 KB |
| `sitemap_xml` | Sitemap Structure Parser | `DIRECT_TARGET_PROBE` | LOW | 15s | 512 KB | 512 KB |
| `extract_links` | Internal & External Link Harvester | `DIRECT_TARGET_PROBE` | LOW | 15s | 1 MB | 2 MB |
| `extract_js_urls` | JavaScript Asset Harvester | `DIRECT_TARGET_PROBE` | LOW | 15s | 1 MB | 2 MB |
| `tech_detect` | Technology Fingerprint Heuristics | `DIRECT_TARGET_PROBE` | LOW | 10s | 512 KB | 1 MB |
| `sensitive_files_check` | Exposed Sensitive Files & Endpoints | `DIRECT_TARGET_PROBE` | MEDIUM | 15s | 64 KB | 64 KB |
| `js_secrets_scanner` | JS Bundle Secrets Scanner (Agg: 5MB) | `DIRECT_TARGET_PROBE` | LOW | 20s | 1 MB / file | 2 MB / file |
| `cors_misconfig_check` | CORS Misconfiguration & Origin Probe | `DIRECT_TARGET_PROBE` | LOW | 10s | 32 KB | 32 KB |
| `subdomain_takeover_check` | Subdomain Takeover & Dangling DNS | `DIRECT_TARGET_PROBE` | LOW | 15s | 64 KB | 64 KB |
| **Offline Analytical** | | | | | | |
| `security_headers_score` | Security Headers Evaluation Score | `OFFLINE_ANALYSIS` | LOW | 1s | N/A (Offline) | N/A (Offline) |
| `cve_matcher` | Technology CVE & Flaw Matcher | `OFFLINE_ANALYSIS` | LOW | 5s | N/A (Offline) | N/A (Offline) |

---

## Detailed Tool Specifications

### 1. `dns_lookup`
- **Tier**: External Third-Party Recon | **Risk**: LOW | **Timeout**: 10s | **Max Size**: 32 KB
- **Description**: Uses `dnsjava` to query primary resource records for the target domain against configured upstream DNS resolvers.
- **Parser Notes**: Queries A, AAAA, CNAME, MX, TXT (including SPF and DMARC), and NS records. Raw DNS responses are normalized into JSON arrays.
- **Input Schema**:
  ```json
  { "recordTypes": ["A", "AAAA", "MX", "TXT", "NS"] }
  ```
- **Output Schema**:
  ```json
  {
    "domain": "example.com",
    "records": {
      "A": ["93.184.216.34"],
      "MX": ["10 mail.example.com."],
      "TXT": ["v=spf1 -all"]
    }
  }
  ```

---

### 2. `whois_lookup`
- **Tier**: External Third-Party Recon | **Risk**: LOW | **Timeout**: 15s | **Max Size**: 32 KB
- **Description**: Queries authoritative WHOIS / RDAP registration directories (via port 43 or HTTPS RDAP) to fetch registrar and domain lifecycle records.
- **Network Dependency**: Connects to public TLD registries. Does not connect directly to the target server. If the target host has no public registration (e.g. internal LAN, private IP), fails gracefully with an informative message.
- **Parser Notes**: Captures raw text output and extracts registrar name, creation date, expiration date, and name servers via regex heuristics.
- **Input Schema**:
  ```json
  { "referralDepth": 1 }
  ```
- **Output Schema**:
  ```json
  {
    "raw": "Domain Name: EXAMPLE.COM\r\nRegistrar: ...",
    "registrar": "Example Registrar LLC",
    "createdDate": "1995-08-14T04:00:00Z",
    "expiresDate": "2027-08-13T04:00:00Z"
  }
  ```

---

### 3. `tls_info`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 10s | **Max Size**: 64 KB
- **Description**: Establishes a direct TLS handshake with the target server (port 443) to inspect peer certificates, cipher suites, and supported protocol versions. Uses RFC 6066 SNI and verifies identity according to RFC 9525.
- **Parser Notes**: Parses Java `X509Certificate` chain. Calculates days until expiration, issuer DN, subject DN, SAN (Subject Alternative Names), and negotiated cipher suite.
- **Input Schema**:
  ```json
  { "port": 443 }
  ```
- **Output Schema**:
  ```json
  {
    "protocol": "TLSv1.3",
    "cipherSuite": "TLS_AES_256_GCM_SHA384",
    "subject": "CN=example.com",
    "issuer": "CN=DigiCert Global Root CA",
    "validFrom": "2025-01-01T00:00:00Z",
    "validUntil": "2026-01-01T00:00:00Z",
    "daysRemaining": 84,
    "sanList": ["example.com", "www.example.com"]
  }
  ```

---

### 4. `http_headers`
- **Tier**: Active Direct Target Probe (`DIRECT_TARGET_PROBE`) | **Risk**: LOW | **Timeout**: 10s | **Max Size**: 64 KB
- **Description**: Fetches HTTP response headers from the target server using a GET request (HEAD-like semantics without consuming long bodies) and parses headers into security-relevant categories.
- **Scope Boundary**: Retrieves raw headers, cookie attributes, and server banners without calculating scores. Quantitative scoring (0–100 score and grade) is strictly isolated to the offline tool `security_headers_score` (#10).
- **Parser Notes**: Extracts and canonicalizes headers (lowercased), analyzes `Set-Cookie` directives (`Secure`, `HttpOnly`, `SameSite`), checks for legacy headers (`X-Powered-By`, `Server`).
- **Input Schema**:
  ```json
  { "customPort": null, "followRedirects": false }
  ```
- **Output Schema**:
  ```json
  {
    "statusCode": 200,
    "httpVersion": "HTTP/1.1",
    "headers": { "strict-transport-security": "max-age=31536000", "server": "nginx" },
    "cookies": [ { "name": "SESSIONID", "secure": true, "httpOnly": true, "sameSite": "Lax" } ],
    "serverBanner": "nginx"
  }
  ```

---

### 5. `robots_txt`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 10s | **Max Size**: 128 KB
- **Description**: Retrieves `/robots.txt` directly from the target server and identifies declared user-agents, disallow rules, and sitemap references.
- **Parser Notes**: Parses line-by-line into structured rule blocks. Flags potentially sensitive disallowed paths (e.g., `/admin`, `/backup`, `/api`).
- **Input Schema**:
  ```json
  {}
  ```
- **Output Schema**:
  ```json
  {
    "found": true,
    "userAgents": {
      "*": { "disallowed": ["/admin", "/private"], "allowed": ["/public"] }
    },
    "sitemaps": ["https://example.com/sitemap.xml"]
  }
  ```

---

### 6. `sitemap_xml`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 15s | **Max Size**: 512 KB
- **Description**: Fetches `/sitemap.xml` directly from the target server (or URLs discovered in robots.txt) and parses XML location entries.
- **Parser Notes**: Uses safe XML parser with external entity resolution disabled (preventing XXE). Extracts top 500 URLs, last modified dates, and identifies administrative/login endpoints.
- **Input Schema**:
  ```json
  { "customPath": "/sitemap.xml", "maxUrls": 500 }
  ```
- **Output Schema**:
  ```json
  {
    "urlCount": 42,
    "sampleUrls": ["https://example.com/", "https://example.com/about"],
    "sensitivePathsFound": []
  }
  ```

---

### 7. `extract_links`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 15s | **Max Size**: 1 MB (Wire) / 2 MB (Decompressed)
- **Description**: Retrieves the landing page HTML directly from the target server and parses all anchor (`<a href="...">`) links using `jsoup`.
- **Parser Notes**: Resolves relative links to absolute URLs. Segregates results into internal (same host) and external links.
- **Input Schema**:
  ```json
  { "maxLinks": 200 }
  ```
- **Output Schema**:
  ```json
  {
    "internalLinks": ["https://example.com/contact", "https://example.com/docs"],
    "externalLinks": ["https://github.com/org", "https://twitter.com/org"]
  }
  ```

---

### 8. `extract_js_urls`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 15s | **Max Size**: 1 MB (Wire) / 2 MB (Decompressed)
- **Description**: Parses `<script src="...">` and inline script tags on the target page to enumerate loaded JavaScript bundles.
- **Parser Notes**: Resolves script origins. Flags third-party tracking scripts, CDNs, and inline script hashes.
- **Input Schema**:
  ```json
  {}
  ```
- **Output Schema**:
  ```json
  {
    "scripts": [
      { "src": "https://example.com/static/app.js", "isInternal": true },
      { "src": "https://cdn.jsdelivr.net/npm/vue@3", "isInternal": false }
    ],
    "inlineScriptsCount": 2
  }
  ```

---

### 9. `tech_detect`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 10s | **Max Size**: 512 KB
- **Description**: Probes target server responses (HTTP headers, meta generator tags, cookie names, and script paths) to identify underlying frameworks, web servers, and CMSs.
- **Parser Notes**: Pure heuristic matching against a built-in signature catalog (e.g. `X-Powered-By: PHP`, `wp-content`, `csrftoken`).
- **Input Schema**:
  ```json
  {}
  ```
- **Output Schema**:
  ```json
  {
    "technologies": [
      { "name": "Nginx", "category": "Web Server", "confidence": "HIGH" },
      { "name": "Vue.js", "category": "Frontend Framework", "confidence": "HIGH" }
    ]
  }
  ```

---

### 10. `security_headers_score`
- **Tier**: Offline Analytical | **Risk**: LOW | **Timeout**: 1s | **Max Size**: N/A (Offline)
- **Description**: Purely offline analysis tool evaluating the headers previously captured by `http_headers`. Executes 0 network requests.
- **Parser Notes**: Scores target from 0 to 100 based on standard criteria (OWASP Secure Headers Project): HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Input Schema**:
  ```json
  { "stepId": "uuid-of-http-headers-result" }
  ```
- **Output Schema**:
  ```json
  {
    "score": 60,
    "grade": "C",
    "missingHeaders": ["Content-Security-Policy", "Permissions-Policy"],
    "presentHeaders": ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"],
    "recommendations": [
      "Define a restrictive Content-Security-Policy to mitigate Cross-Site Scripting (XSS)."
    ]
  }
  ```

---

### 11. `sensitive_files_check`
- **Tier**: Active Direct Target Probe | **Risk**: MEDIUM | **Timeout**: 15s | **Max Size**: 64 KB
- **Description**: Probes target server directly for a curated list of top 40 known sensitive files, backup archives, configuration files, and administrative endpoints.
- **Target Paths Checked**:
  - Environment & Configs: `/.env`, `/.env.local`, `/.env.production`, `/docker-compose.yml`, `/config.json`, `/web.config`
  - Version Control: `/.git/HEAD`, `/.git/config`, `/.gitignore`, `/.svn/entries`
  - Spring Boot Actuators: `/actuator`, `/actuator/env`, `/actuator/health`, `/actuator/heapdump`, `/actuator/beans`
  - Backups & Dumps: `/backup.sql`, `/dump.sql`, `/database.sql`, `/backup.zip`, `/site.tar.gz`, `/wp-config.php.bak`
  - IDE & Editors: `/.vscode/sftp.json`, `/.idea/workspace.xml`, `/.DS_Store`
  - Documentation & Debug: `/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`, `/phpinfo.php`
- **Parser Notes**: Differentiates true exposures from custom soft-404 error pages by inspecting content signatures (e.g. verifying `/.git/HEAD` contains `ref: refs/`, verifying `/.env` contains key-value pairs).
- **Input Schema**:
  ```json
  { "customPaths": [], "stopOnFirstExposed": false }
  ```
- **Output Schema**:
  ```json
  {
    "totalChecked": 35,
    "exposedCount": 1,
    "exposedFiles": [
      {
        "path": "/.env",
        "statusCode": 200,
        "contentType": "text/plain",
        "confidence": "HIGH",
        "snippet": "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=***",
        "severity": "CRITICAL"
      }
    ]
  }
  ```

---

### 12. `js_secrets_scanner`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 20s | **Max Size**: 1 MB / file (Wire), 2 MB / file (Decompressed), 5 MB aggregate
- **Description**: Downloads client-side JavaScript bundles identified on the target site and scans their contents using specialized regular expressions and Shannon entropy to detect leaked API keys, tokens, hardcoded credentials, and private endpoints.
- **Secret Signatures Supported**:
  - Cloud Services: AWS Access Key ID (`AKIA[0-9A-Z]{16}`), Google Cloud API Key (`AIza[0-9A-Za-z\\-_]{35}`)
  - Payment Gateways: Stripe Secret / Publishable Key (`(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24}`)
  - Authentication & Tokens: JWT Tokens (`eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+`), GitHub Personal Access Tokens (`ghp_[0-9a-zA-Z]{36}`)
  - Messaging & SaaS: Slack Webhook URLs, Firebase API configurations, Mailgun API Keys
  - Hardcoded Secrets: High-entropy string patterns preceded by `password =`, `secret =`, `apiKey =`
- **Parser Notes**: Extracts matching lines with surrounding context (line numbers), masks middle characters of sensitive values in UI, and calculates confidence ratings.
- **Input Schema**:
  ```json
  { "jsUrls": [], "maxFiles": 10 }
  ```
- **Output Schema**:
  ```json
  {
    "filesScanned": 4,
    "totalSecretsFound": 1,
    "findings": [
      {
        "file": "https://example.com/assets/app.chunk.js",
        "secretType": "Google Cloud API Key",
        "match": "AIzaSyD-***masked***",
        "line": 142,
        "severity": "HIGH"
      }
    ]
  }
  ```

---

### 13. `cors_misconfig_check`
- **Tier**: Active Direct Target Probe | **Risk**: LOW | **Timeout**: 10s | **Max Size**: 32 KB
- **Description**: Directly tests the target application's Cross-Origin Resource Sharing (CORS) implementation against unverified origins to detect trust misconfigurations that allow malicious third-party websites to steal sensitive user data.
- **Test Probes**:
  1. Arbitrary Origin reflection: Sends `Origin: https://attacker.com`
  2. Null Origin trust: Sends `Origin: null`
  3. Prefix/Suffix bypasses: Sends `Origin: https://example.com.attacker.com`
  4. Wildcard check: Evaluates `Access-Control-Allow-Origin: *` in combination with `Access-Control-Allow-Credentials: true`
- **Parser Notes**: Flags critical vulnerability if the server reflects arbitrary or null origins while concurrently returning `Access-Control-Allow-Credentials: true`.
- **Input Schema**:
  ```json
  { "customOrigins": [] }
  ```
- **Output Schema**:
  ```json
  {
    "isVulnerable": true,
    "vulnerabilityType": "ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS",
    "severity": "HIGH",
    "probes": [
      {
        "testedOrigin": "https://attacker.com",
        "reflectedOrigin": "https://attacker.com",
        "allowCredentials": true,
        "exploitable": true
      }
    ],
    "remediation": "Do not reflect arbitrary Origin headers. Maintain an explicit allowlist of trusted origins."
  }
  ```

---

### 14. `cve_matcher`
- **Tier**: Offline Analytical | **Risk**: LOW | **Timeout**: 5s | **Max Size**: N/A (Offline)
- **Description**: Correlates web server, framework, and library versions identified by `tech_detect` against a local database of known CVEs (Common Vulnerabilities and Exposures) and public security advisories. Executes 0 network requests.
- **Coverage**:
  - Web Servers: Nginx, Apache HTTP Server, Microsoft IIS, Caddy
  - Backend Runtimes & Frameworks: PHP, Python/Django/Flask, Java/Spring Boot, Node.js/Express, Ruby on Rails
  - Content Management Systems: WordPress, Drupal, Joomla, Ghost
  - Frontend Libraries: Outdated jQuery versions, Angular.js 1.x, Bootstrap
- **Parser Notes**: Offline evaluation engine. Normalizes version strings and matches against known vulnerable ranges. Reports CVSS severity scores, CVE identifiers, and public exploit availability status.
- **Input Schema**:
  ```json
  { "stepId": "uuid-of-tech-detect-result" }
  ```
- **Output Schema**:
  ```json
  {
    "matchedCount": 1,
    "vulnerabilities": [
      {
        "component": "Apache HTTP Server",
        "detectedVersion": "2.4.49",
        "cveId": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "HIGH",
        "title": "Path Traversal and File Disclosure",
        "hasPublicExploit": true,
        "description": "A flaw in path normalization in Apache 2.4.49 allows an attacker to map URLs to files outside the document root.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or higher immediately."
      }
    ]
  }
  ```

---

### 15. `subdomain_takeover_check`
- **Tier**: Active Direct Target Probe (`DIRECT_TARGET_PROBE`) | **Risk**: LOW | **Timeout**: 15s | **Max Size**: 64 KB
- **Description**: Inspects CNAME DNS records of the target domain and discovered subdomains for dangling pointers to unclaimed third-party cloud services, directly probing destination HTTP endpoints for canonical fingerprint strings (AWS S3, GitHub Pages, Vercel, Heroku, Azure Websites).
- **Subdomain Origin & Discovery**: The input array `subdomains` accepts specific FQDNs belonging to `*.<target_host>`. If left empty (`[]`), the tool automatically pulls subdomains discovered in preceding session steps (e.g., SAN entries from `tls_info` or discovered links from `extract_links`).
- **PolicyEngine Scope Rules**: As specified in `07-POLICY-ENGINE.md`, checking subdomains of the target host (`*.<target_host>`) is permitted. Destination CNAME HTTP probes are restricted strictly to checking canonical fingerprint signatures of recognized cloud providers, provided all resolved IPs (including CNAME destinations) pass standard PolicyEngine IP filtering (blocking loopback/private/metadata destinations).
- **Vulnerability Mechanism**: If a domain has a DNS CNAME pointing to an external cloud asset (e.g. `sub.example.com CNAME mybucket.s3.amazonaws.com`), but the cloud asset was deleted, an attacker can register that cloud asset name and take full control over `sub.example.com`.
- **Parser Notes**: Queries CNAME records and probes destination HTTP endpoints for canonical fingerprint strings:
  - AWS S3: `"NoSuchBucket"`
  - GitHub Pages: `"There isn't a GitHub Pages site here"`
  - Heroku: `"No such app"`
  - Vercel: `"404: NOT_FOUND"`
- **Input Schema**:
  ```json
  { "subdomains": [] }
  ```
- **Output Schema**:
  ```json
  {
    "isVulnerable": false,
    "cnameRecordsChecked": [
      {
        "domain": "docs.example.com",
        "cnameTarget": "example.github.io",
        "provider": "GitHub Pages",
        "status": "SECURE",
        "fingerprintDetected": null
      }
    ]
  }
  ```
