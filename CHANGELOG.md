# Changelog

All notable changes to the Ospysin platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-16

### Initial Release — Ospysin OSINT & Security Audit Platform

The v0.1.0 milestone delivers the complete, production-hardened, local-first OSINT reconnaissance, vulnerability discovery, and exploit surface auditing platform with offline AI advisory.

### Added

#### Core Architecture & Modular Monolith
- Modular domain packaging under `com.ospysin`:
  - `engagements`, `evidence`, `execution`, `findings`, `identity`, `llm`, `observations`, `policy`, `projects`, `reporting`, `scope`, `sessions`, `shared`, `tools`.
- Spring Boot 3.3.4 + Java 21 runtime with canonical Maven Wrapper (`backend/mvnw`).
- Dual-role PostgreSQL 16 Alpine architecture separating migration administrator (`flyway_user` / `ospysin_admin`) from unprivileged runtime operator (`ospysin_app`).
- Baseline Flyway migration (`V1__init_schema.sql`) provisioning 11 relational tables, JSONB payload storage, foreign key constraints, and WORM triggers.
- Immutable write-once audit ledger (`tool_results`, `audit_events`) enforced via PostgreSQL database triggers blocking `UPDATE`, `DELETE`, and `TRUNCATE`.
- RFC 9457 Problem Details global exception mapping with `invalidParams` validation error breakdown.

#### Security Policy Engine & SSRF Defense
- Comprehensive IP filtering validating all resolved addresses against RFC 6890 IANA Special-Purpose Registries.
- Automatic unwrapping of IPv4-mapped IPv6 addresses (`::ffff:0:0/96`).
- Socket-level IP pinning via custom `DnsResolver` preventing TOCTOU DNS rebinding windows.
- Strict scheme and approved port allowlist restricting outbound probes to `http` and `https`.
- 4-Tier payload bounds:
  - 1 MB raw wire socket cap.
  - Decompression bomb protection with 10x ratio ceiling and 100 KB threshold.
  - 5 MB aggregate memory limit.
  - 10-second connect/read timeout.
- Per-host token-bucket rate limiter enforcing safe execution cadence (1 req/sec default).

#### Audit Session Lifecycle & Scope Attestation
- Cryptographic scope attestation calculating and recording SHA-256 hash (`scope_ack_hash`) over legal authorization statements.
- Session execution modes: `LOCAL` (loopback and RFC 1918 internal lab targets allowed; cloud metadata strictly blocked) and `PUBLIC` (all private and special-purpose IP ranges blocked).
- Session state machine: `ACTIVE` -> `COMPLETED` or `ABORTED`.
- Graceful session abortion with cascading cancellation and epoch lease fencing.

#### 3-Phase PostgreSQL Job Queue & Resilient SSE Hub
- Phase 1 (Queue): Persist `ToolExecution` with status `PENDING` and JSONB input arguments.
- Phase 2 (Lease & Claim): Atomic worker claim via `SELECT ... FOR UPDATE SKIP LOCKED` with lease owner and epoch counter.
- Phase 3 (Complete / Fail): Atomic persistence of `ToolResult`, audit log emission, and lease release.
- Stale-worker watchdog detecting expired leases and transitioning abandoned executions to `FAILED`.
- Resilient Server-Sent Events (SSE) hub (`GET /api/sessions/{id}/events`) with `TransactionSynchronization.afterCommit` event dispatching preventing phantom event leaks.

#### 15-Tool Inspection Catalog across 3 Canonical Tiers
- **Tier 1: External Third-Party Recon (2 Tools)**:
  - `dns_lookup`: DNS record enumeration (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`) via `dnsjava` with SPF/DMARC posture analysis.
  - `whois_lookup`: Authoritative registration query via RDAP with fallback to RFC-compliant WHOIS port 43.
- **Tier 2: Active Direct Target Probes (11 Tools)**:
  - `tls_info`: Direct TLS handshake analyzing peer certificates, validity, cipher suites, protocol versions, and RFC 9525 SAN matching.
  - `http_headers`: Non-destructive `GET`/`HEAD` probe evaluating security headers, cookie flags (`Secure`, `HttpOnly`, `SameSite`), and server banners.
  - `robots_txt`: Robot exclusion protocol parser identifying disallowed endpoints and sitemap references.
  - `sitemap_xml`: Safe XML structure harvester (`XMLConstants.FEATURE_SECURE_PROCESSING`) discovering endpoints (capped at 1,000 URLs).
  - `extract_links`: HTML anchor parser using Jsoup extracting internal and external links.
  - `extract_js_urls`: JavaScript tag and asset harvester discovering client-side routes.
  - `tech_detect`: Heuristic technology fingerprinter identifying web servers, reverse proxies, and CMS platforms with confidence scores.
  - `sensitive_files_check`: Safe byte inspection probing for exposed configuration files, git repos, and backups without false-positive 200 OKs.
  - `js_secrets_scanner`: High-entropy scanner detecting leaked API keys, tokens, and private keys in client bundles.
  - `cors_misconfig_check`: Origin reflection probe testing arbitrary and null origins with credentials.
  - `subdomain_takeover_check`: CNAME inspector verifying dangling aliases pointing to unclaimed cloud services.
- **Tier 3: Offline Analytical Tools (2 Tools)**:
  - `security_headers_score`: Purely offline 0-100 grading engine evaluating header posture previously captured by `http_headers`.
  - `cve_matcher`: Offline correlation engine matching fingerprinted software against local CVE catalog.

#### Offline Local AI Advisor (Dolphin3-Cyber via Ollama)
- Host-managed Ollama inference client connecting to `hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M`.
- Context budgeter enforcing strict 1,450-token prompt budget.
- Untrusted tool output sandboxing (`<untrusted_tool_output>` XML boundary) to defend against indirect prompt injection.
- Structured JSON output parsing (`comment`, `suggested_tool`, `suggested_reason`).
- Registered tool allowlist verification ensuring model cannot recommend unregistered or unsafe actions.
- Interactive tactical chat endpoint (`POST /api/sessions/{id}/llm/chat`) with real-time SSE reply streaming.

#### Frontend SPA & 4-Panel Workspace
- Modern Vue 3 Composition API with `<script setup lang="ts">`, PrimeVue components, Tailwind CSS styling, and Pinia reactive stores.
- Screen 0 (Login View): Credentials form with field-level RFC 9457 error callouts.
- Screen 1 (Session List View): Paginated session table with status pills, target URLs, mode badges, and quick filters.
- Screen 2 (New Session Setup Modal): Target URL validation, `LOCAL`/`PUBLIC` mode selector, and mandatory scope attestation gate.
- Screen 3 (4-Panel Session Workspace View):
  - Left Panel: Categorized 15-tool catalog with prerequisite detection.
  - Center Panel: Step timeline, dual-view inspector (Parsed / Raw Output), automated observations list.
  - Right Panel: AI Advisor commentary card, one-click suggested tool runner, interactive tactical chat.
  - Bottom Panel: Real-time SSE streaming log with log-level filter, auto-scroll lock, and collapse toggles.
- Screen 4 (Standalone Printable Report View): Clean report preview in a sandboxed iframe with HTML download and print/PDF buttons.
- Findings Curation Drawer: Observation-to-finding promotion, confidence/severity curation, evidence excerpt linking, and status transitions with mandatory rejection reason.

#### Container Hardening & Local Deployment
- Multi-stage Dockerfiles:
  - Backend: `eclipse-temurin:21-jdk-alpine` builder -> `eclipse-temurin:21-jre-alpine` runtime.
  - Frontend: `node:22-alpine` builder -> `nginxinc/nginx-unprivileged:1.27-alpine` runtime.
- Non-root user execution (`USER 10001:10001`) across containers.
- Read-only root filesystems (`read_only: true`) paired with isolated `tmpfs` mounts.
- Linux capability dropping (`cap_drop: ["ALL"]`) and `no-new-privileges: true`.
- Loopback-by-default port bindings (`${APP_BIND_HOST:-127.0.0.1}`).
- Container healthchecks verifying readiness every 10–15s.
- Nginx reverse proxy configuration with SPA fallback, defensive security headers (CSP, X-Frame-Options, X-Content-Type-Options), and unbuffered SSE streaming (`proxy_buffering off; proxy_cache off;`).

#### Automated Quality Gates & CI Pipeline
- GitHub Actions CI workflow (`.github/workflows/ci.yml`) running backend Maven verification (with Testcontainers PostgreSQL 16) and frontend Vitest + Playwright suites.
- JaCoCo line coverage enforcement (>= 80% line coverage gate on backend).
- Vitest unit/component suite (133 tests passed, >= 60% line coverage gate on frontend).
- End-to-End browser suite (`frontend/e2e/ospysin-workflow.spec.ts`) verifying the full operator workflow across all 5 screens in headless Chromium.
