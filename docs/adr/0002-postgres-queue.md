# ADR 0002: PostgreSQL-Backed Job Queue vs External Broker

## Status
Accepted

## Context
Executing security tools can take several seconds due to network round-trips and timeouts. Asynchronous execution requires a queue mechanism to schedule, track, and monitor tool execution tasks.

Industry standard message brokers like Apache Kafka or RabbitMQ offer advanced pub/sub features, but introducing them creates substantial operational penalties for local installations:
- Additional heavyweight background daemons consuming 500MB–1GB+ RAM.
- Separate port management and configuration burden.
- Distributed transaction challenges (dual-write dilemma between database and broker).

## Decision
We utilize a **PostgreSQL-backed queue pattern** using `tool_executions` and relational state with session-level row-locking (`SELECT id FROM audit_sessions WHERE id = :id FOR UPDATE`) and row-level task acquisition (`SELECT ... FOR UPDATE SKIP LOCKED`).

Key architectural invariants:
1. **Three-Phase Decoupled Transactions**:
   - *Phase 1 (Ingestion Tx)*: Web request thread validates active session state, enqueues task as `PENDING`, logs audit event, commits, and returns `202 Accepted`.
   - *Phase 2 (Claim Tx)*: Worker thread locks the parent session row, claims the oldest `PENDING` task, transitions status to `RUNNING`, sets `lease_owner`, increments `lease_epoch`, sets `lease_expires_at`, and commits.
   - *Non-Transactional Phase*: Worker executes network socket inspection outside any database transaction, preventing connection pool exhaustion.
   - *Phase 3 (Persistence Tx & Fencing)*: Worker atomically updates `tool_executions` guarded by `lease_epoch == :claimedEpoch AND session.state == 'ACTIVE'`. Persists immutable `tool_results` and audit log. If watchdog reclaimed the lease or the session was aborted, late writes are fenced out and no partial/interrupted socket result is saved to `tool_results`.
2. **Concurrency Scope**: Concurrency is strictly sequential within a session: at most **one** `RUNNING` execution per session. Rapid tool triggers enqueue as `PENDING` rather than launching concurrent socket probes. Parallelism across distinct sessions remains unconstrained. Duplicate identical invocations within a session return `409 Conflict`.
3. **Crash Recovery & Retries**: `PENDING` tasks survive restarts. An `ExecutionWatchdog` reclaims stale `RUNNING` tasks whose leases expired. Terminal target network timeouts are NEVER retried to prevent traffic amplification. Only internal JVM crashes may be retried at most once for idempotent tools.

## Consequences
### Positive:
- Zero additional infrastructure components; uses the already-running PostgreSQL 16 container.
- Strict concurrency control: Session-level locking eliminates race conditions across concurrent workers.
- Resilience: Monotonic lease epochs fence out zombie workers; crash watchdog guarantees no orphaned running state.
- Decoupled transactions: Remote network latency never blocks database connection pools.
- Full forensic visibility: Task statuses, timestamps, and parameters are directly inspectable via SQL.

### Negative:
- High queue throughput (>10,000 tasks/sec) would cause database write contention. For Ospysin's workload (1–2 tool executions per second), this overhead is negligible.

## Alternatives Considered
- **Apache Kafka**: Overkill; excessive operational and memory overhead.
- **RabbitMQ**: Rejected to keep the local Docker Compose footprint minimal.
- **Redis (Celery / BullMQ)**: Avoided to eliminate an extra persistent store dependency.
