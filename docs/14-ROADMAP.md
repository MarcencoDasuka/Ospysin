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

### Phase 0: Repository & Skeleton Setup
- Initialize Git repository.
- Establish clean directory layout with `.gitkeep` markers.
- Create multi-stack `.gitignore` (Java, Node, IDE, `.env`).
- Configure standard `.editorconfig` (LF, UTF-8, 2/4 spaces).
- Commit initial repository skeleton under MIT license.

### Phase 1: Documentation Specification Suite
Create and verify all 16 architectural documents (docs/00 through docs/15) plus core Architecture Decision Records (ADRs).
- `00-VISION.md`: Objectives, personas, non-goals, v1 success criteria.
- `01-SCOPE.md`: Clear boundary between v1 registered tools and deferred destructive exploitation.
- `02-ARCHITECTURE.md`: Modular monolith design, decoupled transaction boundaries, Mermaid sequence diagrams.
- `03-DOMAIN-MODEL.md`: Domain entities, lifecycle invariants, Mermaid ER diagram.
- `04-API-CONTRACTS.md`: REST endpoints, RFC 9457 error responses with invalidParams extension, SSE event stream.
- `05-TOOL-CATALOG.md`: Specifications, schemas for 15 tools organized across 3 canonical tiers.
- `06-LLM-INTEGRATION.md`: Ollama client contract, prompt designs, advisor boundaries.
- `07-POLICY-ENGINE.md`: SSRF defense, DNS rebinding mitigation, 4-tier payload bounds, IP safety.
- `08-THREAT-MODEL.md`: STRIDE threat modeling and architectural mitigations.
- `09-LEGAL-AND-ETHICS.md`: Written authorization requirement, scope checkbox, legal compliance.
- `10-UI-UX-SPEC.md`: 4-panel workspace, ASCII wireframes, reactive UI states.
- `11-DATA-MODEL.md`: Relational PostgreSQL tables, foreign keys, JSONB columns, Flyway migration plan.
- `12-DEPLOYMENT.md`: Docker Compose deployment, host-bound Ollama integration, backup procedures.
- `13-TESTING-STRATEGY.md`: Unit testing, Testcontainers integration tests, Playwright E2E.
- `14-ROADMAP.md`: Phased roadmap and step-by-step master plan.
- `15-GLOSSARY.md`: Authoritative domain terminology and taxonomy.
- `adr/*`: Architectural Decision Records for core structural choices.

### Phase 2: Sign-Off & Verification
- Comprehensive review of all documents against real-world security and engineering constraints.
- Formal approval before any backend or frontend code is written.

### Phase 3: Backend Foundation (Spring Boot 3.3.x + Java 21)
- Spring Boot skeleton with domain modules: `com.ospysin.{identity,projects,engagements,scope,sessions,tools,policy,execution,observations,findings,evidence,reporting,llm,shared}`.
- Flyway migration `V1__init.sql` creating relational schema and constraints.
- JPA domain entities with UUID primary keys and optimistic locking.
- Initial integration tests with Testcontainers PostgreSQL.
- `/api/health` health-check endpoint.

### Phase 4: Frontend Foundation (Vue 3 + TypeScript + Vite)
- Vue 3 project with Pinia, Vue Router, PrimeVue, and Axios.
- Typed API client parsing RFC 9457 Problem Details.
- Base layout and API connectivity verification against `/api/health`.

### Phase 5: First Tool End-to-End (`http_headers`)
- `OspysinTool` interface, `ToolInput`, and `ToolResult` contracts.
- `HttpHeadersTool` implementation (response header normalization and cookie security; scoring isolated to `security_headers_score`).
- `PolicyEngine` v1 implementing URL validation and private IP checks.
- Session lifecycle service and execution event publishing.
- Session workspace UI with tool catalog, step history, and result display.
- Playwright E2E verification of session creation and tool execution.

### Phase 6: Local LLM Integration (Ollama + Dolphin3-Cyber)
- Spring RestClient integration with Ollama.
- Structured comment generation (`comment`, `suggested_tool`, `suggested_reason`).
- Advisor panel UI displaying contextual findings and one-click tool suggestion triggers.
- Isolated integration tests with mock responses and real Ollama instances.

### Phase 7: Tool Catalog Completion (Remaining 14 Tools, Completing All 15 Tools)
Implement remaining 14 reconnaissance, vulnerability assessment, and exploit surface discovery tools (`http_headers` implemented in Phase 5):
- **External Third-Party Recon**:
  1. `dns_lookup` (dnsjava)
  2. `whois_lookup` (RFC-compliant whois client)
- **Active Direct Target Probes**:
  3. `tls_info` (Java SSLSocket / certificate chain parser)
  4. `robots_txt` (Robots.txt parser)
  5. `sitemap_xml` (Sitemap XML analyzer)
  6. `extract_links` (Jsoup HTML link collector)
  7. `extract_js_urls` (Jsoup script tag & JS asset harvester)
  8. `tech_detect` (Heuristic web technology detector)
  9. `sensitive_files_check` (Probe for exposed `/.env`, `/.git`, config files, actuator, dumps)
  10. `js_secrets_scanner` (JS bundle scanner for leaked API keys, JWTs, AWS credentials)
  11. `cors_misconfig_check` (Probe for arbitrary/null origin reflection with credentials)
  12. `subdomain_takeover_check` (Verify CNAME records for dangling cloud services)
- **Offline Analytical**:
  13. `security_headers_score` (Comprehensive security evaluation engine)
  14. `cve_matcher` (Correlate discovered software versions with known CVE vulnerabilities)

### Phase 8: Findings Management & Reporting
- User-managed findings workflow (`POTENTIAL` → `UNDER_REVIEW` → `CONFIRMED` / `REJECTED`).
- Rejection dialog enforcing mandatory operator justification; rejected findings are excluded from primary report.
- Evidence linking from immutable tool outputs.
- Comprehensive HTML report generation with printable CSS / PDF export (internal session JSON report / audit trail via `GET /api/sessions/{id}/report` is supported in v1; external machine-readable SARIF pipelines deferred to post-v1).

### Phase 9: Hardening, Test Suite & v0.1.0 Release
- Target 80% backend and 60% frontend automated test coverage.
- Full E2E Playwright validation across complete audit lifecycles.
- Disaster recovery and session state restoration testing.
- Final documentation updates, Docker Compose validation, and `v0.1.0` release tagging.

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
