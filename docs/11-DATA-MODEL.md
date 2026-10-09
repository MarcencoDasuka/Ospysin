# 11. Relational Data Model Specification

## Overview
This document defines the relational database architecture in **PostgreSQL 16**. The schema matches the entities established in `03-DOMAIN-MODEL.md`. Migrations are versioned and managed strictly through **Flyway**.

---

## Flyway Migration Strategy
- Migration directory: `backend/src/main/resources/db/migration/`.
- File naming convention: `V<Version>__<Description>.sql` (e.g. `V1__init_schema.sql`).
- Migration validation: Clean database setup is validated on every test run using Testcontainers.

---

## Tables & Schema Specifications

### 1. `users`
- `id` (UUID, PRIMARY KEY)
- `username` (VARCHAR(50), NOT NULL, UNIQUE)
- `password_hash` (VARCHAR(255), NOT NULL)
- `role` (VARCHAR(20), NOT NULL, CHECK: `ADMIN`, `AUDITOR`)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())

### 2. `projects`
- `id` (UUID, PRIMARY KEY)
- `name` (VARCHAR(100), NOT NULL)
- `description` (TEXT)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- `updated_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_projects_name` on `name`.

### 3. `engagements`
- `id` (UUID, PRIMARY KEY)
- `project_id` (UUID, NOT NULL, REFERENCES `projects(id)` ON DELETE CASCADE)
- `title` (VARCHAR(150), NOT NULL)
- `start_date` (DATE NOT NULL)
- `end_date` (DATE)
- `status` (VARCHAR(20), NOT NULL, CHECK: `DRAFT`, `ACTIVE`, `COMPLETED`, `ARCHIVED`)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_engagements_project_id` on `project_id`.

### 4. `scope_assets`
- `id` (UUID, PRIMARY KEY)
- `engagement_id` (UUID, NOT NULL, REFERENCES `engagements(id)` ON DELETE CASCADE)
- `asset_type` (VARCHAR(20), NOT NULL, CHECK: `URL`, `FQDN`, `IP`)
- `value` (VARCHAR(255), NOT NULL)
- `is_wildcard` (BOOLEAN, NOT NULL DEFAULT FALSE)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_scope_assets_engagement_id` on `engagement_id`.

### 5. `audit_sessions`
- `id` (UUID, PRIMARY KEY)
- `engagement_id` (UUID, REFERENCES `engagements(id)` ON DELETE SET NULL)
- `target_url` (VARCHAR(500), NOT NULL)
- `mode` (VARCHAR(20), NOT NULL, CHECK: `LOCAL`, `PUBLIC`)
- `state` (VARCHAR(20), NOT NULL, CHECK: `CREATED`, `ACTIVE`, `PAUSED`, `COMPLETED`, `ABORTED`)
- `scope_acknowledged` (BOOLEAN, NOT NULL DEFAULT FALSE)
- `scope_ack_version` (VARCHAR(20))
- `scope_ack_text` (TEXT)
- `scope_ack_hash` (CHAR(64))
- `scope_ack_timestamp` (TIMESTAMP WITH TIME ZONE)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- `updated_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_sessions_target_url` on `target_url`, `idx_sessions_state` on `state`, `idx_sessions_scope_ack_hash` on `scope_ack_hash`.

### 6. `tool_executions`
- `id` (UUID, PRIMARY KEY)
- `session_id` (UUID, NOT NULL, REFERENCES `audit_sessions(id)` ON DELETE RESTRICT)
- `tool_id` (VARCHAR(50), NOT NULL)
- `status` (VARCHAR(20), NOT NULL, CHECK: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`)
- `lease_owner` (UUID)
- `lease_epoch` (INTEGER NOT NULL DEFAULT 0)
- `lease_expires_at` (TIMESTAMP WITH TIME ZONE)
- `attempts` (INTEGER NOT NULL DEFAULT 0)
- `failure_reason` (VARCHAR(100))
- `duration_ms` (BIGINT, CHECK: `duration_ms IS NULL OR duration_ms >= 0`)
- `started_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- `ended_at` (TIMESTAMP WITH TIME ZONE)
- **Indexes**: `idx_executions_session_id` on `session_id`, `idx_executions_claim` on `(status, created_at)`.

### 7. `tool_results` (Immutable)
- `id` (UUID, PRIMARY KEY)
- `execution_id` (UUID, NOT NULL, UNIQUE, REFERENCES `tool_executions(id)` ON DELETE RESTRICT)
- `raw_output` (TEXT NOT NULL, CHECK: `octet_length(raw_output) <= 1048576`)
- `parsed_data` (JSONB NOT NULL)
- `score` (INTEGER, CHECK: `score IS NULL OR (score >= 0 AND score <= 100)`)
- `has_errors` (BOOLEAN NOT NULL DEFAULT FALSE)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: GIN index `idx_tool_results_parsed_gin` on `parsed_data`.
- **Database Trigger Enforcement**:
  ```sql
  CREATE OR REPLACE FUNCTION prevent_immutable_record_mutation()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION 'Table % is strictly append-only; updates, deletions, and truncations are prohibited.', TG_TABLE_NAME;
  END;
  $$ LANGUAGE plpgsql;

  CREATE TRIGGER trg_tool_results_no_mod
  BEFORE UPDATE OR DELETE ON tool_results
  FOR EACH ROW EXECUTE FUNCTION prevent_immutable_record_mutation();

  CREATE TRIGGER trg_tool_results_no_truncate
  BEFORE TRUNCATE ON tool_results
  FOR EACH STATEMENT EXECUTE FUNCTION prevent_immutable_record_mutation();
  ```

### 8. `observations`
- `id` (UUID, PRIMARY KEY)
- `result_id` (UUID, NOT NULL, REFERENCES `tool_results(id)` ON DELETE RESTRICT)
- `category` (VARCHAR(50), NOT NULL)
- `description` (TEXT NOT NULL)
- `severity_heuristic` (VARCHAR(20), NOT NULL, CHECK: `INFO`, `LOW`, `MEDIUM`, `HIGH`)
- `detected_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_observations_result_id` on `result_id`, GIN full-text index `idx_observations_desc_tsv` using `to_tsvector('english', description)`.

### 9. `findings`
- `id` (UUID, PRIMARY KEY)
- `session_id` (UUID, NOT NULL, REFERENCES `audit_sessions(id)` ON DELETE RESTRICT)
- `title` (VARCHAR(200), NOT NULL)
- `description` (TEXT NOT NULL)
- `severity` (VARCHAR(20), NOT NULL, CHECK: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `confidence` (VARCHAR(20), NOT NULL, CHECK: `TENTATIVE`, `CONFIRMED`)
- `status` (VARCHAR(30), NOT NULL, CHECK: `POTENTIAL`, `UNDER_REVIEW`, `CONFIRMED`, `REJECTED`, `ARCHIVED`)
- `rejection_reason` (TEXT)
- `remediation` (TEXT)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- `updated_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_findings_session_id` on `session_id`.

### 10. `evidence`
- `id` (UUID, PRIMARY KEY)
- `finding_id` (UUID, NOT NULL, REFERENCES `findings(id)` ON DELETE CASCADE)
- `result_id` (UUID, NOT NULL, REFERENCES `tool_results(id)` ON DELETE RESTRICT)
- `snippet` (TEXT NOT NULL)
- `created_at` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())

### 11. `audit_events` (Append-Only Ledger)
- `id` (UUID, PRIMARY KEY)
- `session_id` (UUID, REFERENCES `audit_sessions(id)` ON DELETE RESTRICT)
- `event_type` (VARCHAR(50), NOT NULL)
- `payload` (JSONB NOT NULL)
- `timestamp` (TIMESTAMP WITH TIME ZONE, NOT NULL, DEFAULT NOW())
- **Indexes**: `idx_audit_events_session_id` on `session_id`, `idx_audit_events_timestamp` on `timestamp`.
- **Database Trigger Enforcement**:
  ```sql
  CREATE TRIGGER trg_audit_events_no_mod
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION prevent_immutable_record_mutation();

  CREATE TRIGGER trg_audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION prevent_immutable_record_mutation();
  ```

---

## Database Privilege Separation & Immutability Boundaries

1. **Role Separation**:
   - DDL Migration Role (`flyway_user`): Schema owner; executes versioned DDL migrations.
   - Application Runtime Role (`ospysin_app`): Granted `SELECT`, `INSERT` on `tool_results`, `audit_events`. Explicitly `REVOKE UPDATE, DELETE, TRUNCATE ON tool_results, audit_events FROM ospysin_app;`.
2. **Epistemic Immutability Limits**:
   - Database triggers and role grants guarantee immutability against application-level ORM mutations, operator user errors, and unprivileged database sessions.
   - They **do not** provide hardware WORM guarantees against host superusers (`postgres` / DBA) who possess administrative bypass rights. Full chain-of-custody relies on cryptographic hashes recorded in the immutable audit log.
