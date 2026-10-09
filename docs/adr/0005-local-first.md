# ADR 0005: Local-First Operation with Zero Cloud Dependencies

## Status
Accepted

## Context
Many modern developer and security tools rely on cloud infrastructure, SaaS databases, or proprietary cloud LLM APIs (OpenAI, Anthropic, Google Gemini).

In professional vulnerability auditing, target URLs, internal IPs, and discovered security weaknesses are highly sensitive data. Transmitting this intelligence to third-party cloud services introduces significant risks:
- Exposure of client vulnerabilities to third-party telemetry and AI training sets.
- Violation of non-disclosure agreements (NDAs) and data residency laws (GDPR).
- Inability to conduct assessments in air-gapped or restricted offline environments.

## Decision
Ospysin adopts a strict **Local-First Architecture**:
1. All application components (Frontend, Spring Boot backend, PostgreSQL) run locally or inside local Docker containers.
2. AI inference is performed purely on the host machine via **Ollama** running open-weight models (`hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M`).
3. Zero telemetry, crash reporting, or external API calls are made to Ospysin servers or third parties.

## Consequences
### Positive:
- Total confidentiality: Sensitive vulnerabilities never leave the auditor's local machine.
- Air-gap capability: The tool works without active internet connectivity when auditing internal LAN or localhost applications.
- Zero ongoing subscription or API inference costs.

### Negative:
- Local hardware must have adequate memory and compute capability to run quantized 8B parameter LLMs (recommended: 16GB RAM, modern CPU or 6GB+ VRAM GPU).
- LLM quality is bound by local model capacity compared to frontier cloud models.

## Alternatives Considered
- **Cloud LLM API Integration (OpenAI / Claude / Gemini API)**: Rejected to preserve target confidentiality and offline independence.
