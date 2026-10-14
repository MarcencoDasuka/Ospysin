# Ospysin Development Roadmap & Master Plan

## Overview & Core Principles

This document serves as the master execution roadmap for **Ospysin** (OSINT & Security Audit Platform). The methodology strictly enforces a **documentation-first, vertical-slice, AI-agent-assisted** implementation discipline.

### Immutable Principles
1. **Self-Defense & Proactive Hardening**: The core mission is finding vulnerabilities and exploit surfaces in user-owned systems to patch them before malicious exploitation occurs.
2. **User-Driven, Not AI-Driven**: The human operator chooses the tool. The LLM advises and identifies exploit surfaces, but the human approves every execution.
3. **Deterministic Tools, Specialized Exploitation Advisor**: Inspection tools are reproducible and structured. The LLM actively highlights attack vectors and vulnerabilities.
4. **Documentation-First**: Zero lines of application code are produced until every document and contract is reviewed and approved.
5. **Vertical Slices**: Every development cycle yields a complete, testable user scenario across database, API, and UI.
6. **Local-First**: The complete stack (LLM, database, backend, frontend) operates entirely on local hardware without cloud dependence.
7. **Audit Trail**: Every action, tool invocation, raw payload, and decision is recorded in an immutable ledger.

---

## Repository Skeleton Layout

```text
ospysin/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── .gitignore
├── .editorconfig
├── docs/
│   ├── 00-VISION.md
│   ├── 01-SCOPE.md
│   ├── 02-ARCHITECTURE.md
│   ├── 03-DOMAIN-MODEL.md
│   ├── 04-API-CONTRACTS.md
│   ├── 05-TOOL-CATALOG.md
│   ├── 06-LLM-INTEGRATION.md
│   ├── 07-POLICY-ENGINE.md
│   ├── 08-THREAT-MODEL.md
│   ├── 09-LEGAL-AND-ETHICS.md
│   ├── 10-UI-UX-SPEC.md
│   ├── 11-DATA-MODEL.md
│   ├── 12-DEPLOYMENT.md
│   ├── 13-TESTING-STRATEGY.md
│   ├── 14-ROADMAP.md
│   ├── 15-GLOSSARY.md
│   ├── adr/
│   │   ├── 0001-modular-monolith.md
│   │   ├── 0002-postgres-queue.md
│   │   ├── 0003-llm-as-advisor.md
│   │   ├── 0004-user-triggered-tools.md
│   │   └── 0005-local-first.md
│   ├── audits/
│   └── remediation/
├── backend/
├── frontend/
├── infra/
│   ├── docker-compose.yml
│   ├── .env.example
│   └── init-db/
└── scripts/
    └── bundle-phase.ps1
```

---

## Detailed Execution Phases

### Phase 0: Repository & Skeleton Setup (Completed)
- Initialize Git repository and baseline branch structure.
- Establish clean directory layout with `.gitkeep` markers for `backend/`, `frontend/`, `infra/`, `scripts/`.
- Create multi-stack `.gitignore` (Java, Node, IDE, `.env`, snapshots).
- Configure standard `.editorconfig` (LF, UTF-8, 2/4 spaces).
- Establish initial repository skeleton under MIT license.

### Phase 1: Documentation Specification Suite — 16 Docs & 5 ADRs (Completed)
Author and cross-verify the comprehensive documentation specification suite:
- `00-VISION.md`: Objectives, operator personas, non-goals, v1 success criteria.
- `01-SCOPE.md`: Strict boundaries between registered inspection tools and prohibited destructive exploits.
- `02-ARCHITECTURE.md`: Modular monolith design, decoupled transactions, state machines, sequence diagrams.
- `03-DOMAIN-MODEL.md`: Domain entities, lifecycle invariants, Mermaid ER diagram, state transitions.
- `04-API-CONTRACTS.md`: REST endpoints, RFC 9457 Problem Details with `invalidParams`, SSE event stream contracts.
- `05-TOOL-CATALOG.md`: Specifications, input/output schemas for 15 tools across 3 canonical tiers.
- `06-LLM-INTEGRATION.md`: Ollama client contract, Dolphin3-Cyber prompt designs, 1,450-token budgeter, anti-hallucination guards.
- `07-POLICY-ENGINE.md`: SSRF defense, RFC 6890 IP filtering, IPv4-mapped IPv6 unwrapping, IP pinning `DnsResolver`, 4-tier payload bounds.
- `08-THREAT-MODEL.md`: STRIDE threat modeling, trust boundaries, attack surface analysis, and architectural mitigations.
- `09-LEGAL-AND-ETHICS.md`: Written authorization requirement, cryptographic attestation, legal boundaries.
- `10-UI-UX-SPEC.md`: 4-panel workspace, ASCII wireframes, reactive UI states, design tokens.
- `11-DATA-MODEL.md`: Relational PostgreSQL tables, foreign keys, JSONB columns, Flyway migration plan, index strategy.
- `12-DEPLOYMENT.md`: Docker Compose deployment, host-bound Ollama integration, backup/restore procedures.
- `13-TESTING-STRATEGY.md`: Testing pyramid, Testcontainers PostgreSQL integration tests, WireMock, Playwright E2E.
- `14-ROADMAP.md`: Granular phased execution roadmap.
- `15-GLOSSARY.md`: Authoritative domain terminology, comparison matrices, taxonomy.
- `adr/*`: Architectural Decision Records (ADR-0001 through ADR-0005).

### Phase 2: Sign-Off, Verification & Audit Bundler Infrastructure (Completed)
- Comprehensive cross-verification of all specifications against security invariants and engineering constraints.
- Implement PowerShell audit bundling script (`scripts/bundle-phase.ps1`) for generating verifiable phase snapshots.
- Formal sign-off and baseline freeze before application implementation.

### Phase 3: Backend Foundation, Flyway V1 Schema & Domain Entities (Completed)
- Initialize Spring Boot 3.3.x + Java 21 project with canonical Maven Wrapper (`backend/mvnw*`).
- Modular package structure: `com.ospysin.{engagements,evidence,execution,findings,identity,llm,observations,policy,projects,reporting,scope,sessions,shared,tools}`.
- Flyway V1 baseline migration (`V1__init_schema.sql`): 11 relational tables, foreign keys, CHECK constraints, indexes, and dual-user role separation (`ospysin_admin` / `ospysin_app`).
- 11 JPA domain entities with protected no-arg constructors, immutable entities annotated with `@Immutable`, and explicit private `@Builder` constructors excluding `id` with null-safe constructor defaults.
- Security baseline: `Argon2id` password hashing (`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`), bootstrap admin user initialization (`admin` / ephemeral password).
- Global exception handling (`GlobalExceptionHandler`): RFC 9457 `ProblemDetail` responses for `400 Bad Request` (JSON syntax, parameter type mismatch, validation), `404 Not Found`, `409 Conflict`, `422 Policy Violation`, and `500 Internal Server Error`.
- Liveness & readiness health check (`GET /api/health`) with Ollama connectivity probe and trailing-slash normalization.
- Test suite: 23 unit and Testcontainers integration tests passing against PostgreSQL 16 Alpine.

### Phase 4: Operator Session Authentication & CSRF Security
- Endpoints: `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`.
- State: Stateful HTTP session authentication using `JSESSIONID` cookie (`HttpOnly; SameSite=Strict; Path=/`).
- CSRF Protection: `CookieCsrfTokenRepository.withHttpOnlyFalse()` providing `XSRF-TOKEN` cookie, validated via `X-XSRF-TOKEN` request header on state-mutating requests.
- Authorization: Role-based access control (`ROLE_ADMIN`, `ROLE_OPERATOR`) with security filter chain rules.
- Test suite: MockMvc unit tests for authentication success, invalid credentials, session invalidation, CSRF token validation, and unauthenticated access rejection.

### Phase 5: Frontend Foundation, Typed RFC 9457 API Client & Login View
- Frontend stack: Vue 3, TypeScript, Vite, Pinia, Vue Router, PrimeVue with Tailwind CSS theme.
- Typed HTTP Client: Axios wrapper handling RFC 9457 `ProblemDetail` parsing, automatic CSRF token header forwarding (`X-XSRF-TOKEN`), and 401 redirect interceptors.
- Authentication Store: Pinia `useAuthStore` tracking current operator state and session expiration.
- UI Views:
  - Screen 0 (Login View): Credentials form with RFC 9457 field-level error rendering (`invalidParams`).
  - Top Navigation Bar: Application brand, backend connectivity badge (`/api/health`), and authenticated operator profile / logout button.
- Verification: Component tests and end-to-end login flow validation.

### Phase 6: Network Policy Engine & SSRF / DNS Rebinding Guard
- Core Engine: `PolicyEngine` evaluating target URLs, domains, and IP addresses against strict scope and network rules.
- SSRF & Private Network Filter:
  - Block loopback (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), documentation IPs, and multicast ranges.
  - Unwrap IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) before evaluation.
- DNS Pinning & Rebinding Guard: Custom `DnsResolver` resolving hostnames to IP addresses, verifying all resolved addresses against policy, and pinning the resolved IP for the downstream HTTP client to eliminate TOCTOU DNS rebinding windows.
- Payload Bounds: Enforce 4-tier bounds (1 MB raw response cap, 5 MB memory limit, decompression bomb defense, and 10 s read timeout).
- Test suite: Comprehensive unit tests against public targets, internal IPs, cloud metadata endpoints (`169.254.169.254`), and DNS rebinding simulations.

### Phase 7: Audit Session Lifecycle & Scope Attestation API
- REST Endpoints:
  - `POST /api/sessions`: Create new session with target URL, execution mode (`LOCAL` / `PUBLIC`), and scope attestation.
  - `GET /api/sessions`: Paginated list of sessions with status and target metadata.
  - `GET /api/sessions/{id}`: Detailed session state, associated engagement, and target details.
  - `POST /api/sessions/{id}/complete`: Gracefully mark active session as completed.
  - `POST /api/sessions/{id}/abort`: Abort running session and cancel all pending tool executions.
- Cryptographic Scope Attestation:
  - Calculate and store SHA-256 `scope_ack_hash` over the displayed authorization statement text.
  - Record attestation version, text, hash, and timestamp in `AuditSession`.
- Auto-provision default `Project`, `Engagement`, and `ScopeAsset` when creating ad-hoc sessions.
- Invariants: Disallow tool queuing on completed or aborted sessions; prevent state transitions violating session state machine.
- Test suite: Integration tests for session lifecycle, optimistic locking, and attestation persistence.

### Phase 8: Session List & New Session Setup Modal UI
- Screen 1 (Session List View):
  - DataTable of existing audit sessions with target URL, mode badge (`LOCAL` / `PUBLIC`), state pill, start timestamp, and action buttons.
  - Quick filters: Active, Completed, Aborted.
- Screen 2 (New Session Setup Modal):
  - Target URL input with real-time format validation.
  - Execution mode radio selection (`LOCAL` private audit vs. `PUBLIC` internet target).
  - Scope Attestation Gate: Mandatory checkbox with legally compliant authorization text; creation button disabled until operator explicitly checks acknowledgment.
- Pinia Store: `useSessionStore` managing active session list and selection.

### Phase 9: Tool Catalog Registry, PostgreSQL Job Queue & SSE Hub
- Tool Contract: `OspysinTool` interface defining metadata, input schema validation, execution logic, and observation extraction.
- Catalog Registry: `ToolCatalog` registering tools and exposing `GET /api/tools` with tool capabilities and prerequisites.
- PostgreSQL 3-Phase Job Queue:
  - Phase 1 (Queue): Enqueue `ToolExecution` with status `PENDING` and JSONB input parameters.
  - Phase 2 (Lease & Claim): Worker poll using `SELECT ... FOR UPDATE SKIP LOCKED`, assigning lease owner and epoch fencing.
  - Phase 3 (Complete / Fail): Atomically persist `ToolResult`, update status (`COMPLETED` / `FAILED`), release lease, and write `AuditEvent`.
- Execution Safeguards:
  - Per-host rate limiting (default 1 request/sec per target).
  - `ExecutionWatchdog` detecting expired leases and transitioning stalled tasks to `FAILED`.
- Server-Sent Events (SSE) Hub:
  - `GET /api/sessions/{id}/events`: Resilient SSE stream emitting session state changes, tool execution lifecycle events, and findings updates.
  - `TransactionSynchronization.afterCommit` event dispatching preventing phantom event leaks.
- Test suite: Concurrency tests with multi-threaded workers, lease fencing verification, and SSE subscription tests.

### Phase 10: Core HTTP & TLS Direct Probes
- `http_headers` Tool:
  - Issue safe `GET` / `HEAD` request to target using pinned IP from Policy Engine.
  - Capture HTTP status, protocol version, and raw headers.
  - Extract cookies and verify security flags (`Secure`, `HttpOnly`, `SameSite`).
  - Extract automated `Observation` records for missing security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`).
- `tls_info` Tool:
  - Establish TLS handshake using Java `SSLSocketFactory` with SNI.
  - Inspect certificate chain, issuer, validity period, cipher suite, and TLS protocol version.
  - Verify Subject Alternative Names (SAN) per RFC 9525.
  - Detect deprecated protocols (TLS 1.0, 1.1) and weak ciphers.
- Test suite: WireMock HTTP header tests and mock SSL server integration tests.

### Phase 11: Session Workspace UI — 4-Panel Layout & Live SSE Stream
- Screen 3 (Session Workspace View):
  - **Left Panel (Tool Catalog)**: Grouped tool categories (HTTP/TLS, Recon, Crawling, Analysis, Active Probes) with execution trigger buttons.
  - **Center Panel (Results & Execution Viewer)**:
    - Step history timeline with execution status pills.
    - Result inspector with syntax-highlighted raw output, parsed key-value data, and tabs for Headers/Cookies/TLS details.
    - Memory optimization using `shallowRef` for large output datasets.
  - **Bottom Panel (Live SSE Event Log)**:
    - Real-time streaming log of audit events with timestamps and log levels.
    - Auto-scroll lock toggle and log filter by event type.
    - Proper SSE connection teardown in Vue `onUnmounted` hook.
- Pinia Store: `useWorkspaceStore` binding SSE stream to reactive view models.

### Phase 12: Local LLM Advisory Integration
- Spring Client: `OllamaClient` connecting to local Ollama instance (`Dolphin3-Cyber`).
- Prompt Engineering & Context Management:
  - Context budgeter enforcing strict 1,450-token prompt budget.
  - Rolling session summary integrating past tool outputs.
  - Tagged untrusted boundary: Wrap tool outputs in `<untrusted_tool_output>` XML tags with instructions to ignore prompt injection attempts.
  - Output schema: Structured JSON (`comment`, `suggested_tool`, `suggested_reason`).
  - Tool allowlist verification: Validate suggested tool against 15 registered tools before presenting to operator.
- Endpoints & Streaming:
  - Async generation triggered upon tool completion, streaming comments via SSE to workspace.
  - Interactive operator chat: `POST /api/sessions/{id}/llm/chat`.
- Right Panel (Advisor UI):
  - Streaming advisory comments, risk highlights, and one-click "Execute Suggested Tool" action.

### Phase 13: External Third-Party Recon Tools
- `dns_lookup` Tool:
  - Query DNS records (`A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CNAME`, `CAA`, `PTR`) via `dnsjava`.
  - Validate DNSSEC records and identify SPF/DMARC email security configurations.
  - Extract automated observations for missing DMARC/SPF or exposed internal DNS names.
- `whois_lookup` Tool:
  - Query registration data using RDAP (Registration Data Access Protocol) with fallback to RFC-compliant WHOIS port 43.
  - Strict referral loop protection and policy-validated referral hosts.
  - Parse registrar, creation date, expiration date, name servers, and registrant organization (redacting private individuals).
- Test suite: WireMock RDAP responses and isolated DNS tests.

### Phase 14: Web Crawling & Asset Harvester Probes
- `robots_txt` Tool:
  - Fetch and parse `/robots.txt` per standard robot exclusion protocol.
  - Extract `Disallow` and `Allow` rules, sitemap references, and crawl-delay directives.
  - Flag sensitive paths exposed in `Disallow` directives (e.g., `/admin/`, `/backup/`, `/.git/`).
- `sitemap_xml` Tool:
  - Fetch `/sitemap.xml` and recursive sitemap indexes with XXE-safe XML parser (`XMLConstants.FEATURE_SECURE_PROCESSING`).
  - Harvest URL endpoints, change frequency, and last modification dates (capped at 1,000 URLs).
- `extract_links` Tool:
  - Parse target HTML via Jsoup to discover internal and external anchor links (`<a href>`), forms (`<form action>`), and API endpoints.
- `extract_js_urls` Tool:
  - Extract external script references (`<script src>`) and inline script content.
  - Regex heuristics to extract relative API routes and endpoint paths defined within client-side bundles.
- Test suite: Jsoup HTML parsing unit tests and XML parser XXE injection attack tests.

### Phase 15: Technology Fingerprinting & Offline Analytical Engine
- `tech_detect` Tool:
  - Heuristic detection of web servers, backend frameworks, CMSs, JavaScript libraries, and reverse proxies from HTTP headers, cookies, meta tags, and script URLs.
  - Confidence scoring (`CONFIRMED`, `PROBABLE`, `TENTATIVE`).
- `security_headers_score` Tool:
  - Offline analytical tool calculating 0–100 security score based on discovered headers, TLS configuration, and cookie policies.
  - Detailed score breakdown with positive marks and weighted deductions for critical omissions.
- `cve_matcher` Tool:
  - Correlate detected technologies and versions against local offline CVE vulnerability database.
  - Session BOLA protection: verify session scope before querying or returning CVE advisories.
  - Output CVE IDs, CVSS scores, vulnerability descriptions, and recommended mitigation links.
- Test suite: Technology detection fixture tests, grading calculation unit tests, and CVE matcher tests.

### Phase 16: Active Vulnerability & Exploit Surface Probes
- `sensitive_files_check` Tool:
  - Probe for common exposed sensitive files: `/.env`, `/.git/HEAD`, `/config.json`, `/wp-config.php.bak`, `/actuator/env`, `/server-status`.
  - Safe byte inspection verifying expected magic signatures rather than blind 200 OK responses (preventing false positives from custom 404 pages).
- `js_secrets_scanner` Tool:
  - Download discovered JavaScript bundles (capped at 5 MB).
  - Scan content using high-entropy calculation and regex patterns for leaked secrets: API keys (AWS, Google, GitHub, Slack), private keys, JWT tokens, and hardcoded database connection strings.
- `cors_misconfig_check` Tool:
  - Send requests with arbitrary `Origin` and `null` origin headers to assess Cross-Origin Resource Sharing policy.
  - Flag critical misconfigurations where `Access-Control-Allow-Origin` reflects untrusted origins with `Access-Control-Allow-Credentials: true`.
- `subdomain_takeover_check` Tool:
  - Inspect CNAME records of target subdomains for unresolved aliases pointing to unclaimed cloud providers (AWS S3, GitHub Pages, Heroku, Azure).
- Test suite: Sensitive file fixture tests, secret detection regex/entropy tests, and CORS response verification.

### Phase 17: Findings Curation, Evidence Linking & Standalone HTML/PDF Reporting
- Findings Workflow API:
  - `POST /api/sessions/{id}/findings`: Create finding from observation or operator input.
  - `PUT /api/sessions/{id}/findings/{findingId}`: Update title, description, severity, and remediation advice.
  - `POST /api/sessions/{id}/findings/{findingId}/status`: Transition status (`POTENTIAL` → `UNDER_REVIEW` → `CONFIRMED` / `REJECTED`).
  - Mandatory rejection reason: Enforce non-empty `rejection_reason` when marking status as `REJECTED`; rejected findings are excluded from primary report.
- Evidence Linking API:
  - `POST /api/findings/{id}/evidence`: Link immutable excerpt/slice from `ToolResult` to substantiate finding.
- Standalone HTML/PDF Report:
  - `GET /api/sessions/{id}/report`: Full session audit report in JSON or standalone HTML.
  - Report features: Executive summary, target scope, methodology, findings severity distribution chart, detailed vulnerabilities with evidence snippets, and operator audit trail.
  - Printable CSS stylesheet for pixel-perfect browser "Save as PDF" rendering.
- UI Components:
  - Workspace Findings Drawer: Review, edit, confirm, or reject findings with evidence viewer.
  - Screen 4 (Printable Report View): Clean, standalone report layout with export buttons.
- Test suite: Findings lifecycle integration tests and report generation tests.

### Phase 18: End-to-End Playwright Suite, Docker Compose Hardening, CI Pipeline & `v0.1.0` Release
- End-to-End Test Suite:
  - Playwright test scenarios covering full operator workflow: Login → Session Setup → Attestation Check → Tool Execution → Real-Time SSE Log → Findings Curation → Report Export.
- Docker Compose Hardening:
  - Multi-stage Dockerfiles for backend (distroless/Alpine JRE 21) and frontend (Nginx unprivileged).
  - Health checks, resource limits, read-only root filesystems, non-root users (`uid: 10001`).
  - Ollama container integration with automated model pulling (`dolphin3-cyber`).
- CI/CD Pipeline:
  - GitHub Actions workflow: linting, Maven clean verify, Testcontainers PostgreSQL tests, Playwright E2E run, and JaCoCo coverage validation (>= 80% backend, >= 60% frontend).
- Release Tagging:
  - Final documentation freeze, release notes, license verification, and `v0.1.0` Git tag creation.

---

## Scope Boundaries: What Is Excluded in v1
- Destructive exploitation (destructive payloads, arbitrary code execution, database corruption).
- Indiscriminate high-volume brute-force and volumetric DDoS flooding (to preserve system stability).
- Multi-agent orchestration frameworks or automated autonomous tool chaining without operator confirmation.
- Vector databases, embeddings, or RAG infrastructure.
- Distributed message brokers (Kafka/RabbitMQ) or Kubernetes clusters.
- Machine-readable SARIF vulnerability exchange pipeline (deferred to post-v1; internal session JSON report / audit trail is supported in v1 via `/api/sessions/{id}/report`).
- Document management for uploaded physical scans/PDFs of testing permissions (v1 uses cryptographic server-side attestation).
- Direct arbitrary host shell command execution.
- External paid intelligence APIs (Shodan, VirusTotal, Censys).
- Cloud deployment architectures or multi-tenant SaaS features.
