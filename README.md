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

## Repository Structure

```text
ospysin/
├── README.md               # Project overview, philosophy, and documentation index
├── LICENSE                 # Open source license (MIT)
├── SECURITY.md             # Security policy and vulnerability disclosure guidelines
├── CONTRIBUTING.md         # Contribution guidelines and engineering standards
├── .gitignore              # Multi-stack ignore rules (Java, Node, IDE, DB, logs)
├── .editorconfig           # Code formatting rules (UTF-8, LF, standard indentations)
├── docs/                   # Complete architectural and operational specifications
│   ├── 00-VISION.md        # Vision, goals, non-goals, and personas
│   ├── 01-SCOPE.md         # In-scope and out-of-scope boundaries for v1
│   ├── 02-ARCHITECTURE.md  # High-level architecture, tech stack, and data flows
│   ├── 03-DOMAIN-MODEL.md  # Entities, relationships, and lifecycle invariants
│   ├── 04-API-CONTRACTS.md # REST endpoints, RFC 9457 payloads, and SSE stream
│   ├── 05-TOOL-CATALOG.md  # Detailed catalog of all 15 tools across 3 canonical tiers
│   ├── 06-LLM-INTEGRATION.md # Offline Ollama integration and advisor contracts
│   ├── 07-POLICY-ENGINE.md # SSRF protection, IP filtering, and safety policies
│   ├── 08-THREAT-MODEL.md  # STRIDE security threat modeling and mitigations
│   ├── 09-LEGAL-AND-ETHICS.md # Authorization boundaries, ethical guidelines, laws
│   ├── 10-UI-UX-SPEC.md    # Screen layouts, 4-panel workspace, ASCII wireframes
│   ├── 11-DATA-MODEL.md    # Relational PostgreSQL schema and migration strategy
│   ├── 12-DEPLOYMENT.md    # Local setup, Ollama provisioning, Docker Compose
│   ├── 13-TESTING-STRATEGY.md # Unit, integration, contract, and E2E testing
│   ├── 14-ROADMAP.md       # Phased roadmap and step-by-step master plan
│   ├── 15-GLOSSARY.md      # Authoritative domain terminology and taxonomy
│   └── adr/                # Architecture Decision Records
│       ├── 0001-modular-monolith.md
│       ├── 0002-postgres-queue.md
│       ├── 0003-llm-as-advisor.md
│       ├── 0004-user-triggered-tools.md
│       └── 0005-local-first.md
├── backend/                # Spring Boot 3.3.x backend (Java 21) & embedded execution worker
├── frontend/               # Vue 3 + TypeScript + Vite + PrimeVue UI
├── infra/                  # Infrastructure configurations (Docker Compose, .env)
│   ├── docker-compose.yml
│   ├── .env.example
│   └── init-db/
└── scripts/                # Local automation, seed, and maintenance scripts
```

---

## Documentation Index (Logical Reading Sequence)

To understand the system from rationale to implementation, read the documentation suite in this dependency sequence:

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
| **17** | [SECURITY.md](./SECURITY.md) / [CONTRIBUTING.md](./CONTRIBUTING.md) | Project vulnerability reporting & contribution rules | Complete |

### Architecture Decision Records (ADRs)
- [ADR 0001: Modular Monolith](./docs/adr/0001-modular-monolith.md)
- [ADR 0002: PostgreSQL-backed Job Queue](./docs/adr/0002-postgres-queue.md)
- [ADR 0003: LLM as Advisory Sounding Board](./docs/adr/0003-llm-as-advisor.md)
- [ADR 0004: User-Triggered Tool Invocations](./docs/adr/0004-user-triggered-tools.md)
- [ADR 0005: Local-First Offline Operation](./docs/adr/0005-local-first.md)

---

## Technology Stack

- **Backend**: Java 21, Spring Boot 3.3.x, Spring Data JPA, Spring Security, Flyway, Testcontainers.
- **Frontend**: Vue 3, TypeScript 5, Vite, Pinia, PrimeVue, Tailwind CSS.
- **Storage**: PostgreSQL 16 (relational entities + JSONB payloads).
- **AI Engine**: Ollama running locally (`hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M` via GGUF).
- **Orchestration**: Docker Compose.

---

## Legal & Ethical Usage

Ospysin is intended exclusively for authorized security reviews, internal systems auditing, vulnerability management on self-hosted infrastructure, and cybersecurity research where explicit permission has been obtained. Unapproved reconnaissance or exploitation against third-party systems is unlawful under national and international computer fraud regulations. Consult [09-LEGAL-AND-ETHICS.md](./docs/09-LEGAL-AND-ETHICS.md) before deployment.
