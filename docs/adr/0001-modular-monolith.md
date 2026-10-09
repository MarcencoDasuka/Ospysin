# ADR 0001: Modular Monolith Architecture for v1

## Status
Accepted

## Context
Ospysin requires coordinating web inspection tools, network security policies, persistent storage, and local LLM advisory. A common architectural choice for security platforms is a distributed microservices pattern (e.g. separate scanner service, policy service, LLM service, and API gateway).

However, Ospysin is explicitly designed as a local-first workbench running on an individual auditor's machine. Microservices introduce significant operational complexity:
- Multiple container processes consuming host RAM/CPU.
- Inter-service networking latency and serialization overhead.
- Complex distributed transaction and event consistency management.
- Risk of network policy bypasses across internal service hops.

## Decision
We adopt a **modular monolith** architecture implemented in Spring Boot 3.3.x with Java 21.

Key principles:
1. Clear package and module isolation: `identity`, `projects`, `sessions`, `tools`, `policy`, `execution`, `llm`, `reporting`.
2. In-process invocations between modules to eliminate network overhead.
3. Single database schema under unified transactional boundaries.

## Consequences
### Positive:
- Minimal footprint on host machines; single JVM process.
- Direct, atomic transactions across session status and audit events.
- Zero network latency for internal service communication.
- Straightforward local debugging and single-step breakpoints.

### Negative:
- Long-running scanning tasks share JVM resources with API request threads (mitigated by bounded thread pools).
- High-volume concurrency is constrained by the host machine's hardware.

## Alternatives Considered
- **Microservices with gRPC / REST**: Rejected due to disproportionate deployment and cognitive overhead for a local tool.
- **Serverless / Lambda Functions**: Rejected due to strict offline requirement.
