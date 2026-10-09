# 01. Scope Specification (v1)

## Overview
This document defines the strict functional and architectural boundaries for version 1 (v1) of Ospysin. Setting explicit scope invariants prevents scope creep, ensures uncompromising software stability, and keeps development aligned with our core tenets.

---

## In-Scope Features & Acceptance Criteria

### 1. OSINT Reconnaissance & Exploit Surface Discovery Tools
- **Scope**: Exactly 15 deterministic reconnaissance, inspection, and vulnerability discovery tools organized across three canonical tiers:
  - **External Third-Party Recon (2)**: `dns_lookup`, `whois_lookup` (Passive queries against external registries and DNS servers).
  - **Active Direct Target Probes (11)**: `tls_info`, `http_headers`, `robots_txt`, `sitemap_xml`, `extract_links`, `extract_js_urls`, `tech_detect`, `sensitive_files_check`, `js_secrets_scanner`, `cors_misconfig_check`, `subdomain_takeover_check` (Direct TCP/TLS handshakes or HTTP requests to the target host).
  - **Offline Analytical (2)**: `security_headers_score`, `cve_matcher` (Offline computation over captured evidence; zero network I/O).
- **Acceptance Criteria**: Tools safely gather intelligence, fingerprint technologies, detect configuration weaknesses, probe for exposed credentials and sensitive files, and expose attack surfaces. They execute deterministically to uncover active vulnerabilities without destructive Denial-of-Service or unguided payloads.

### 2. User-Triggered Execution Model
- **Scope**: All tool executions originate from direct user interaction in the UI and are dispatched asynchronously via `202 Accepted` queueing.
- **Acceptance Criteria**: Backend rejects any tool run request lacking an explicit user invocation token. The AI engine is completely decoupled from execution handlers and has zero invocation privileges.

### 3. Local LLM Vulnerability Advisor
- **Scope**: Integration with a local Ollama runtime hosting the pinned cybersecurity model `hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M`.
- **Acceptance Criteria**: LLM consumes structured step outputs within a strict 1,450-token prompt ceiling, returns concise technical analysis identifying active vulnerabilities and exploit surfaces, and suggests targeted next inspection tools. Suggestions are validated against the 15-tool registry before reaching the UI.

### 4. Session-Based Audit Trail & Findings Lifecycle
- **Scope**: Ephemeral and persistent session tracking recording every configuration, tool run, raw payload, and decision.
- **Acceptance Criteria**: Each session stores append-only entries in PostgreSQL, protected by database triggers against `UPDATE`, `DELETE`, and `TRUNCATE`. Curated findings support `POTENTIAL`, `UNDER_REVIEW`, `CONFIRMED`, and `REJECTED` states (with mandatory justification for rejections). History can be exported as an immutable JSON audit log.

### 5. Standalone HTML Reporting
- **Scope**: Client-side / backend report renderer compiling session metadata, executed steps, findings, and evidence.
- **Acceptance Criteria**: Report renders cleanly in modern browsers, contains no external CDN scripts, and supports direct browser PDF printing.

### 6. Localhost and LAN Target Support (Self-Defense Auditing)
- **Scope**: Full ability to audit user-owned applications and infrastructure running on `localhost`, private RFC 1918 subnets, or public internet domains.
- **Acceptance Criteria**: Policy engine provides two distinct modes (`LOCAL` and `PUBLIC`). `LOCAL` mode allows full testing of local services and private LAN environments for self-defense; `PUBLIC` mode prevents accidental requests to private addresses when targeting public domains.

### 7. PostgreSQL Persistent Storage
- **Scope**: Single-node PostgreSQL 16 database storing relational entities and unstructured tool outputs via JSONB.
- **Acceptance Criteria**: Schema migrations managed exclusively via Flyway. Clean test spin-up achieved with Testcontainers.

### 8. Docker Compose Local Deployment
- **Scope**: Orchestration configuration bundling backend, frontend, and PostgreSQL services.
- **Acceptance Criteria**: `docker-compose up` launches the entire platform locally, seamlessly routing host-bound inference requests to Ollama via `host.docker.internal`.

---

## Out-of-Scope Features & Deferral Rationale

| Feature | Category | Deferral Rationale |
| :--- | :--- | :--- |
| **Destructive Exploitation (Payload Injection)** | System Safety | Automated execution of destructive payloads (e.g., dropping DB tables, executing shellcode) risks corrupting target environments. V1 focuses on non-destructive discovery and proof-of-concept verification. |
| **High-Volume Brute-Force & Flooding** | Network Safety | Unthrottled volumetric fuzzing degrades service availability and causes self-inflicted Denial of Service. |
| **Autonomous Multi-Agent Swarms** | Architecture | Uncontrolled autonomous agent loops create non-deterministic network behavior and eliminate human oversight. |
| **RAG & Vector Databases** | Architecture | Adds heavy vector index dependencies and complexity without material value for structured single-target audit sessions. |
| **Cloud Hosting & Multi-Tenant SaaS** | Deployment | Contradicts the local-first philosophy and compromises operator privacy regarding audited assets. |
| **Arbitrary Shell Execution** | Security | Introduces massive remote code execution (RCE) and host compromise vectors. |
| **Paid Intelligence APIs** | Operations | Commercial API keys (Shodan, Censys, VirusTotal) impose financial friction and external data leakage. |
| **Mobile Applications** | UI / UX | Security analysis workflows demand multi-pane desktop layouts, terminal-style inspector trees, and code inspection viewers. |
