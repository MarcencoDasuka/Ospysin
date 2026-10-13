# 13. Automated Testing Strategy

## Overview
Quality and regression prevention are guaranteed via a multi-tier test pyramid. Strict test coverage boundaries prevent untested code merges and verify safety invariants before production builds.

---

## Testing Pyramid & Targets

```text
       /\
      /  \      E2E Tests (Playwright) [Critical User Flows]
     /----\
    /      \    Integration Tests (Testcontainers, WireMock)
   /--------\
  /          \  Unit Tests (JUnit 5, Mockito, Vitest) [80% Backend / 60% Frontend]
 /------------\
```

- **Backend Target Coverage**: ≥ 80% line coverage (enforced via JaCoCo).
- **Frontend Target Coverage**: ≥ 60% line coverage (enforced via Vitest / Istanbul).

---

## Test Categories

### 1. Unit Tests
- **Policy Engine**: Verifies IP filtering, IANA Special-Purpose Registries (RFC 6890), cloud metadata (AWS/GCP/Azure), IPv4-mapped IPv6 unwrapping (`::ffff:0:0/96`), and redirect revalidation across exhaustive edge cases (octal/hex encodings, IPv6 brackets).
- **DNS Rebinding Harness**: Uses a custom in-memory `NameResolver` mock that flips from a legitimate public IP on initial check to a loopback address on connection time; verifies that socket-level IP pinning aborts the connection.
- **Payload Limits & Bomb Defense**: Tests the 4-tier limits:
  - Wire limit (1 MB socket cap).
  - Decompression bomb guard: Verifies that ratio expansion check activates when decompressed size $D > 100 \text{ KB}$ and aborts when ratio $> 10$ (e.g. 150 KB from 5 KB wire aborted; 50 KB from 1 KB allowed).
  - Aggregate multi-asset limit (5 MB across assets).
  - Persisted row cap (1 MB max `tool_results` payload).
- **Tool Parsers**: Validates header normalizers, robots.txt analyzers, XML sitemap parsers, and regex heuristics using static mock responses.
- **DTO Validation**: Ensures Jakarta Bean Validation annotations enforce format rules.
- **LLM Context Budgeting**: Verifies token calculation via BPE tokenizer (confirming input prompt never exceeds 1,450 tokens including Llama-3 chat template markers).

### 2. Integration Tests
- **Clock Injection (`java.time.Clock`)**:
  - All time-dependent services (`AuditSessionService`, `ToolExecutionWorker`, `PolicyEngine`) MUST accept an injected `java.time.Clock` bean.
  - Enables deterministic testing of lease expiration, timeouts, and stale-worker recovery without brittle `Thread.sleep()` calls.
- **PostgreSQL Queue Concurrency & Fencing (`@DataJpaTest` / Testcontainers)**:
  - **Deterministic Barrier Test**: Uses `CountDownLatch` or `CompletableFuture` to run concurrent worker claim queries (`SELECT ... FOR UPDATE`); asserts that exactly one worker claims the `RUNNING` lease while the other receives `Optional.empty()`.
  - **Asynchronous Acceptance Test**: Asserts that `POST /api/sessions/{id}/tools/{toolId}/run` persists a `PENDING` execution and returns `202 Accepted` immediately without blocking on a simulated slow worker task.
  - **Fencing Test**: Simulates an expired lease epoch ($N$) attempting to write a `COMPLETED` status after a recovery worker has already claimed epoch $N+1$; asserts zero rows updated and rejection of stale worker writes.
- **Database Immutability & Privileges Integration Test**:
  - Connects via direct JDBC using the runtime application role (`ospysin_app`).
  - Verifies that `UPDATE`, `DELETE`, and `TRUNCATE` statements against `tool_results` and `audit_events` are strictly rejected with database exceptions raised by triggers.
  - Verifies that foreign key deletion of an `audit_sessions` parent row is blocked by `ON DELETE RESTRICT` constraints on child `tool_results`.
- **Tool Execution with WireMock**:
  - Sets up in-memory HTTP servers responding with custom headers, redirects, and delays.
  - Tests timeout handling, payload cap enforcement, and terminal failure semantics.

### 3. API Contract & Lifecycle Tests
- Validates that Spring `@RestController` endpoints adhere strictly to `04-API-CONTRACTS.md`.
- Verifies that error conditions return valid RFC 9457 Problem Details JSON bodies (with `invalidParams` on 422 Unprocessable Entity).
- Tests session completion (`POST /api/sessions/{id}/complete`) and abortion (`POST /api/sessions/{id}/abort`), verifying that pending executions are marked `CANCELLED` and running executions are fenced.
- Tests findings rejection (`POST /api/findings/{id}/reject`) with mandatory `reason` payload, verifying that rejected findings are excluded from the default executive summary.

### 4. End-to-End (E2E) Browser Tests (Playwright)
Automated browser suite executing complete vertical user scenarios:
1. Operator logs in via `/login` and navigates to the home page.
2. Operator creates new audit session with target URL (`http://localhost:8080/mock-target`) in `LOCAL` mode.
3. Operator checks scope acknowledgment and clicks "Start Session".
4. Operator triggers `Run HTTP Headers`.
5. UI displays `202 Accepted` queue transition, worker picks up execution, center panel displays parsed security headers.
6. Right panel receives and displays simulated LLM advice and suggestion button.
7. Operator curates a finding and rejects a false positive.
8. Operator completes the session and exports the standalone report.

### 5. LLM Testing Strategy
- **Deterministic Pipeline Tests**: All standard unit and integration tests use a stubbed `LlmClient` returning fixed, deterministic JSON responses to guarantee fast, offline CI builds.
- **Live Model Integration Suite (`@LlmIT`)**:
  - Isolated test class requiring a live local Ollama instance running `hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M`.
  - Evaluates real prompt comprehension, JSON compliance, input budgeting, and tool suggestion allowlist validation.
  - Excluded from default fast test runs (`mvn test -DexcludeTags=LlmIT`).

---

## Continuous Integration (CI) Workflow

GitHub Actions runs on every Pull Request to `main`:
1. **Lint & Code Style**: Checkstyle (Java) and ESLint + Prettier (Vue).
2. **Backend Verification**: `./mvnw test` with JaCoCo coverage validation (≥ 80%).
3. **Frontend Verification**: `pnpm test` and `pnpm build`.
4. **Security Scan**: Dependency-Check / Trivy scanning for vulnerable libraries.
