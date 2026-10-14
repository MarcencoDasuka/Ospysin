-- ============================================================================
-- V1__init_schema.sql: Initial Relational Database Schema for Ospysin
-- Target Database: PostgreSQL 16+
-- Reference: docs/11-DATA-MODEL.md, docs/03-DOMAIN-MODEL.md
-- ============================================================================

-- Ensure pgcrypto extension for UUID generation if needed
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- 1. users
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('ADMIN', 'AUDITOR')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 2. projects
-- ----------------------------------------------------------------------------
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_projects_name ON projects(name);

-- ----------------------------------------------------------------------------
-- 3. engagements
-- ----------------------------------------------------------------------------
CREATE TABLE engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    title VARCHAR(150) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE,
    status VARCHAR(20) NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'COMPLETED', 'ARCHIVED')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_engagements_project_id ON engagements(project_id);

-- ----------------------------------------------------------------------------
-- 4. scope_assets
-- ----------------------------------------------------------------------------
CREATE TABLE scope_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_type VARCHAR(20) NOT NULL CHECK (asset_type IN ('URL', 'FQDN', 'IP')),
    value VARCHAR(255) NOT NULL,
    is_wildcard BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scope_assets_engagement_id ON scope_assets(engagement_id);

-- ----------------------------------------------------------------------------
-- 5. audit_sessions
-- ----------------------------------------------------------------------------
CREATE TABLE audit_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    target_url VARCHAR(500) NOT NULL,
    mode VARCHAR(20) NOT NULL CHECK (mode IN ('LOCAL', 'PUBLIC')),
    state VARCHAR(20) NOT NULL CHECK (state IN ('ACTIVE', 'COMPLETED', 'ABORTED')),
    scope_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    scope_ack_version VARCHAR(20),
    scope_ack_text TEXT,
    scope_ack_hash CHAR(64),
    scope_ack_timestamp TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_target_url ON audit_sessions(target_url);
CREATE INDEX idx_sessions_state ON audit_sessions(state);
CREATE INDEX idx_sessions_scope_ack_hash ON audit_sessions(scope_ack_hash);

-- ----------------------------------------------------------------------------
-- 6. tool_executions
-- ----------------------------------------------------------------------------
CREATE TABLE tool_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES audit_sessions(id) ON DELETE RESTRICT,
    tool_id VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    input_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    lease_owner UUID,
    lease_epoch INTEGER NOT NULL DEFAULT 0,
    lease_expires_at TIMESTAMP WITH TIME ZONE,
    attempts INTEGER NOT NULL DEFAULT 0,
    failure_reason VARCHAR(100),
    duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    ended_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_executions_session_id ON tool_executions(session_id);
CREATE INDEX idx_executions_claim ON tool_executions(status, created_at);

-- ----------------------------------------------------------------------------
-- 7. tool_results (Immutable)
-- ----------------------------------------------------------------------------
CREATE TABLE tool_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL UNIQUE REFERENCES tool_executions(id) ON DELETE RESTRICT,
    raw_output TEXT NOT NULL CHECK (octet_length(raw_output) <= 1048576),
    parsed_data JSONB NOT NULL,
    score INTEGER CHECK (score IS NULL OR (score >= 0 AND score <= 100)),
    has_errors BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tool_results_parsed_gin ON tool_results USING GIN (parsed_data);

-- ----------------------------------------------------------------------------
-- 8. observations
-- ----------------------------------------------------------------------------
CREATE TABLE observations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    result_id UUID NOT NULL REFERENCES tool_results(id) ON DELETE RESTRICT,
    category VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    severity_heuristic VARCHAR(20) NOT NULL CHECK (severity_heuristic IN ('INFO', 'LOW', 'MEDIUM', 'HIGH')),
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_observations_result_id ON observations(result_id);
CREATE INDEX idx_observations_desc_tsv ON observations USING GIN (to_tsvector('english', description));

-- ----------------------------------------------------------------------------
-- 9. findings
-- ----------------------------------------------------------------------------
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES audit_sessions(id) ON DELETE RESTRICT,
    observation_id UUID REFERENCES observations(id) ON DELETE SET NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence VARCHAR(20) NOT NULL DEFAULT 'TENTATIVE' CHECK (confidence IN ('TENTATIVE', 'CONFIRMED')),
    status VARCHAR(30) NOT NULL CHECK (status IN ('POTENTIAL', 'UNDER_REVIEW', 'CONFIRMED', 'REJECTED', 'ARCHIVED')),
    rejection_reason TEXT,
    remediation TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_session_id ON findings(session_id);
CREATE INDEX idx_findings_observation_id ON findings(observation_id);

-- ----------------------------------------------------------------------------
-- 10. evidence
-- ----------------------------------------------------------------------------
CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    result_id UUID NOT NULL REFERENCES tool_results(id) ON DELETE RESTRICT,
    snippet TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_evidence_finding_id ON evidence(finding_id);
CREATE INDEX idx_evidence_result_id ON evidence(result_id);

-- ----------------------------------------------------------------------------
-- 11. audit_events (Append-Only Ledger)
-- ----------------------------------------------------------------------------
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES audit_sessions(id) ON DELETE RESTRICT,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'SESSION_STARTED',
        'SESSION_COMPLETED',
        'SESSION_ABORTED',
        'SCOPE_ACKNOWLEDGED',
        'POLICY_EVALUATED',
        'TOOL_TRIGGERED',
        'TOOL_FINISHED',
        'LLM_QUERY',
        'LLM_COMMENT',
        'FINDING_CREATED',
        'FINDING_REJECTED'
    )),
    payload JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_events_session_id ON audit_events(session_id);
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);

-- ----------------------------------------------------------------------------
-- Database Trigger Enforcement for Immutability
-- ----------------------------------------------------------------------------
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

CREATE TRIGGER trg_audit_events_no_mod
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_record_mutation();

CREATE TRIGGER trg_audit_events_no_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_immutable_record_mutation();

-- ----------------------------------------------------------------------------
-- Default System Container Initialization
-- ----------------------------------------------------------------------------
INSERT INTO projects (id, name, description, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default Project',
    'System container for ad-hoc audit engagements and sessions.',
    NOW(),
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- Privilege Separation (Runtime Role ospysin_app)
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ospysin_app') THEN
        GRANT USAGE ON SCHEMA public TO ospysin_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ospysin_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ospysin_app;

        -- Explicitly enforce append-only for immutable tables
        REVOKE UPDATE, DELETE, TRUNCATE ON tool_results, audit_events FROM ospysin_app;
    END IF;
END $$;
