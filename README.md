# Ospysin — OSINT & Security Audit Platform

> **Local-first, deterministic vulnerability discovery & OSINT platform with offline AI advisory for self-defense.**

Ospysin is an open-source, local-first platform engineered for comprehensive OSINT reconnaissance, vulnerability discovery, and exploit surface auditing. Built primarily for **proactive self-defense** and securing your own infrastructure, it pairs predictable, deterministic inspection tools with an offline cybersecurity AI advisor (Dolphin3-Cyber via Ollama). The platform and local LLM are specifically configured to surface active vulnerabilities, exploitable misconfigurations, and perimeter weak points before external threat actors can abuse them.

---

## Core Philosophy & Tenets

1. **Self-Defense & Proactive Hardening**  
   The primary mission is discovering exploit surfaces and vulnerabilities in your own applications and servers first. By auditing assets from an attacker's perspective, operators identify and patch critical holes before deployment.
2. **User-Driven, Not AI-Driven**  
   The human operator retains full command. Tools are only executed when explicitly selected and confirmed by the user. The AI model never acts autonomously or launches unapproved actions.
3. **Deterministic Tools, Specialized AI Exploitation Advisor**  
   Inspection tools produce exact, repeatable, structured outputs. The local LLM acts as an offensive/defensive advisor, actively interpreting outputs to point out active vulnerabilities, explain exploitability, and recommend verification steps.
4. **Documentation-First**  
   Not a single line of application code is written until every architectural contract, domain model, security policy, and API specification has been designed, reviewed, and finalized.
5. **Vertical Slices**  
   Development proceeds in end-to-end functional slices: each milestone represents a fully functional capability across database, backend logic, and frontend interaction.
6. **Local-First & Offline Resilience**  
   Zero reliance on external cloud services or proprietary third-party APIs. Application binaries, PostgreSQL database, and inference engine (Ollama with local models such as Dolphin3-Cyber) run entirely on local hardware, ensuring complete confidentiality.
7. **Immutable Forensic Audit Trail**  
   Every session initiation, scope acknowledgment, policy decision, tool execution, raw payload, and LLM query is timestamped and recorded in an immutable ledger for legal verification and reproducible reports.

---

## Key Security Invariants & Defensive Architecture

- **SSRF & DNS Rebinding IP Pinning**: Outbound socket connections resolve hostnames via a dedicated `DnsResolver` verifying all resolved addresses against RFC 6890 IANA Special-Purpose Registries, unwrapping IPv4-mapped IPv6 addresses (`::ffff:0:0/96`), and pinning socket connections directly to pre-validated `InetAddress` objects to eliminate Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding windows.
- **4-Tier Payload Bounds**: Multi-layer resource exhaustion defenses:
  - 1 MB raw wire socket cap.
  - Decompression bomb guard (activates when decompressed size $> 100 \text{ KB}$ with ratio $> 10$).
  - 5 MB aggregate memory limit.
  - 10-second connect and read timeout.
- **3-Phase PostgreSQL Job Queue with Lease Epoch Fencing**: Non-blocking job claiming via `SELECT ... FOR UPDATE SKIP LOCKED` pairing lease owners with atomic epoch numbers ($N$). Stale workers attempting to complete an execution after lease recovery ($N+1$) are rejected at the database boundary.
- **Immutable WORM Audit Ledger**: Append-only audit integrity guaranteed via PostgreSQL triggers blocking `UPDATE`, `DELETE`, and `TRUNCATE` operations on `tool_results` and `audit_events`.
- **Untrusted LLM Advisor Boundary**: Local Ollama model (`Dolphin3-Cyber-8B-GGUF:Q4_K_M`) is isolated behind strict context boundaries:
  - 1,450-token context budgeting.
  - Tool outputs wrapped in `<untrusted_tool_output>` delimiters with anti-injection instructions.
  - Strict JSON schema enforcement with tool allowlist verification.
  - The model cannot autonomously dispatch network probes or execute system commands.

---

## Registered Tool Catalog (15 Tools across 3 Canonical Tiers)

| Tier | Tool ID | Display Name | Category | Scope / Input Requirements | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Third-Party Recon** | `dns_lookup` | DNS Record Enumeration | `DNS` | Target Domain / `recordTypes` | Queries `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME` records via `dnsjava` with SPF/DMARC posture analysis. |
| **Tier 1: Third-Party Recon** | `whois_lookup` | WHOIS / RDAP Registration | `WHOIS` | Target Domain / `referralDepth` | Authoritative registration queries via RDAP with fallback to RFC-compliant WHOIS port 43. |
| **Tier 2: Direct Target Probe** | `tls_info` | TLS/SSL Handshake Probe | `TLS` | Target Host / `port` (443) | Inspects certificate chain, validity, ciphers, protocol versions, and RFC 9525 Subject Alternative Names. |
| **Tier 2: Direct Target Probe** | `http_headers` | HTTP Headers & Cookies | `HTTP` | Target URL / `customPort` | Non-destructive `GET`/`HEAD` probe evaluating security headers, cookie flags (`Secure`, `HttpOnly`, `SameSite`), and server banners. |
| **Tier 2: Direct Target Probe** | `robots_txt` | Robots.txt Disallow Probe | `RECON` | Target URL | Fetches `/robots.txt` per robot exclusion standards, extracting disallowed paths and declared sitemaps. |
| **Tier 2: Direct Target Probe** | `sitemap_xml` | Sitemap Structure Parser | `RECON` | Target URL / `customPath` | XXE-safe XML harvester extracting endpoint URLs, change frequencies, and modification dates (capped at 1,000 URLs). |
| **Tier 2: Direct Target Probe** | `extract_links` | Anchor Link Extractor | `CONTENT` | Target URL / `maxLinks` | Parses HTML via Jsoup to discover internal and external links (`<a href>`) and form action endpoints. |
| **Tier 2: Direct Target Probe** | `extract_js_urls` | JavaScript Asset Harvester | `CONTENT` | Target URL | Discovers `<script src>` tags and extracts relative API endpoints defined inside client-side bundles. |
| **Tier 2: Direct Target Probe** | `tech_detect` | Technology Fingerprinter | `RECON` | Target URL | Heuristic detection of web servers, reverse proxies, and CMS platforms with confidence scores. |
| **Tier 2: Direct Target Probe** | `sensitive_files_check` | Sensitive Files Probe | `SECURITY` | Target URL / `customPaths` | Direct probing for exposed config files, git repositories, backups, and debug endpoints with magic byte validation. |
| **Tier 2: Direct Target Probe** | `js_secrets_scanner` | JS Secrets Scanner | `SECURITY` | Target URL / `jsUrls` | High-entropy and regex scanning of loaded JavaScript bundles for exposed API keys, tokens, and private credentials. |
| **Tier 2: Direct Target Probe** | `cors_misconfig_check` | CORS Misconfiguration Probe | `SECURITY` | Target URL / `customOrigins` | Tests CORS implementation against arbitrary and `null` origins with credentials to detect exploitable trust policies. |
| **Tier 2: Direct Target Probe** | `subdomain_takeover_check` | Subdomain Takeover Probe | `DNS` | Target Subdomain | Inspects CNAME records for dangling aliases pointing to unclaimed third-party cloud infrastructure (S3, GitHub, Heroku, Azure). |
| **Tier 3: Offline Analytical** | `security_headers_score` | Security Headers Scoring | `ANALYSIS` | Completed `http_headers` Step | Purely offline 0–100 posture scoring engine evaluating headers and cookies previously captured by `http_headers`. |
| **Tier 3: Offline Analytical** | `cve_matcher` | Offline CVE Vulnerability Matcher | `ANALYSIS` | Completed `tech_detect` Step | Offline correlation of detected software versions against local CVE advisories with CVSS ratings and mitigation links. |

---

## Quickstart & Deployment Guide

### Prerequisites
1. **Operating System**: Windows 10/11 (with WSL2), Linux (Ubuntu 22.04+), or macOS.
2. **Docker & Docker Compose**: Docker Desktop 4.28+ or Docker Engine 26+.
3. **Ollama**: Installed natively on host (enables native GPU acceleration with CUDA, ROCm, or Metal).

### 1. Provision Local AI Model (Ollama)
Install Ollama from [ollama.com](https://ollama.com) and pull the pinned cybersecurity model checkpoint:
```bash
# Pull and start the pinned Dolphin3-Cyber (8B Q4_K_M GGUF) checkpoint
ollama run hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M
```
Verify that Ollama responds locally:
```bash
curl http://localhost:11434/api/tags
```

### 2. Launch Stack via Docker Compose
```bash
cd infra
cp .env.example .env
docker-compose up -d --build
```

Monitor container health:
```bash
docker-compose ps
```

- **Frontend Workbench UI**: `http://127.0.0.1:5173`
- **Backend API & Health Probe**: `http://127.0.0.1:8080/api/health`
- **PostgreSQL**: `127.0.0.1:5432`

---

## Local Developer Environment Setup

### Backend (Spring Boot 3.3.4 + Java 21)
```bash
cd backend
# Linux / macOS:
./mvnw clean spring-boot:run
# Windows PowerShell:
./mvnw.cmd clean spring-boot:run
```

### Frontend (Vue 3 + TypeScript + Vite)
```bash
cd frontend
pnpm install
pnpm dev
```

---

## Automated Testing & Quality Gates

The project enforces strict verification gates across both backend and frontend modules:

### 1. Backend Verification & JaCoCo Coverage Gate
Runs unit tests, WireMock network tests, and Testcontainers PostgreSQL 16 Alpine integration tests with JaCoCo line coverage verification ($\ge 80\%$ line coverage required to pass):
```bash
cd backend
# Linux / macOS:
./mvnw clean verify
# Windows:
./mvnw.cmd clean verify
```

### 2. Frontend Vitest Unit & Component Suite
Runs unit and component tests with Vitest in jsdom environment ($\ge 60\%$ line coverage target):
```bash
cd frontend
pnpm test:run
```

### 3. Frontend Production Build Check
Verifies strict TypeScript typing (`vue-tsc --noEmit`) and Vite asset bundling:
```bash
cd frontend
pnpm build
```

### 4. End-to-End Browser Suite (Playwright)
Executes automated headless Chromium tests verifying the full vertical operator workflow across all 5 screens (Screen 0 Login $\rightarrow$ Screen 1 Session List $\rightarrow$ Screen 2 Scope Attestation Modal $\rightarrow$ Screen 3 4-Panel Workspace, Tool Execution, Live SSE Log, AI Advisor, Tactical Chat, Observation Promotion, Findings Curation, Evidence Linking $\rightarrow$ Screen 4 Standalone Printable Report View):
```bash
cd frontend
pnpm test:e2e
```

---

## Documentation Index

| Order | Document | Focus | Status |
| :---: | :--- | :--- | :--- |
| **1** | [00-VISION.md](./docs/00-VISION.md) | Objectives, personas, non-goals & v1 success criteria | Complete |
| **2** | [15-GLOSSARY.md](./docs/15-GLOSSARY.md) | Domain language: Observation vs Finding vs Evidence | Complete |
| **3** | [01-SCOPE.md](./docs/01-SCOPE.md) | Formal boundaries, included capabilities, deferred items | Complete |
| **4** | [03-DOMAIN-MODEL.md](./docs/03-DOMAIN-MODEL.md) | Core business entities, lifecycle states, Mermaid ER diagram | Complete |
| **5** | [05-TOOL-CATALOG.md](./docs/05-TOOL-CATALOG.md) | Technical specs and schemas for all 15 audit & vulnerability discovery tools | Complete |
| **6** | [02-ARCHITECTURE.md](./docs/02-ARCHITECTURE.md) | Modular monolith architecture, stack, Mermaid flows | Complete |
| **7** | [07-POLICY-ENGINE.md](./docs/07-POLICY-ENGINE.md) | Network safety, SSRF/DNS rebinding defense, per-host limits | Complete |
| **8** | [06-LLM-INTEGRATION.md](./docs/06-LLM-INTEGRATION.md) | Dolphin3-Cyber integration, rolling summary, 2048 token budget | Complete |
| **9** | [09-LEGAL-AND-ETHICS.md](./docs/09-LEGAL-AND-ETHICS.md) | Statutory framework, SHA-256 scope acknowledgment, ethics | Complete |
| **10** | [08-THREAT-MODEL.md](./docs/08-THREAT-MODEL.md) | STRIDE threat matrix and architectural counter-measures | Complete |
| **11** | [04-API-CONTRACTS.md](./docs/04-API-CONTRACTS.md) | REST endpoints, RFC 9457 error format, SSE streaming | Complete |
| **12** | [11-DATA-MODEL.md](./docs/11-DATA-MODEL.md) | PostgreSQL 16 relational schema, Flyway migrations, JSONB | Complete |
| **13** | [10-UI-UX-SPEC.md](./docs/10-UI-UX-SPEC.md) | 4-panel workspace design, states, ASCII wireframes | Complete |
| **14** | [12-DEPLOYMENT.md](./docs/12-DEPLOYMENT.md) | Docker Compose, Ollama host setup, LAN mode, backups | Complete |
| **15** | [13-TESTING-STRATEGY.md](./docs/13-TESTING-STRATEGY.md) | Test pyramid, Testcontainers, Playwright, CI pipelines | Complete |
| **16** | [14-ROADMAP.md](./docs/14-ROADMAP.md) | Master development roadmap & phased execution gates | Complete |
| **17** | [CHANGELOG.md](./CHANGELOG.md) | Version history and release notes | Complete |
| **18** | [SECURITY.md](./SECURITY.md) / [CONTRIBUTING.md](./CONTRIBUTING.md) | Project vulnerability reporting & contribution rules | Complete |

### Architecture Decision Records (ADRs)
- [ADR 0001: Modular Monolith](./docs/adr/0001-modular-monolith.md)
- [ADR 0002: PostgreSQL-backed Job Queue](./docs/adr/0002-postgres-queue.md)
- [ADR 0003: LLM as Advisory Sounding Board](./docs/adr/0003-llm-as-advisor.md)
- [ADR 0004: User-Triggered Tool Invocations](./docs/adr/0004-user-triggered-tools.md)
- [ADR 0005: Local-First Offline Operation](./docs/adr/0005-local-first.md)

---

## Legal & Ethical Usage

Ospysin is intended exclusively for authorized security reviews, internal systems auditing, vulnerability management on self-hosted infrastructure, and cybersecurity research where explicit permission has been obtained. Unapproved reconnaissance or exploitation against third-party systems is unlawful under national and international computer fraud regulations. Consult [09-LEGAL-AND-ETHICS.md](./docs/09-LEGAL-AND-ETHICS.md) before deployment.
