-- ============================================================================
-- V2__findings_curation.sql
-- Findings Curation, Evidence Linking & State Machine Invariants
-- ============================================================================

-- 1. Update findings.status check constraint to support OPEN and FALSE_POSITIVE
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_status_check;
ALTER TABLE findings ADD CONSTRAINT findings_status_check 
    CHECK (status IN ('OPEN', 'POTENTIAL', 'UNDER_REVIEW', 'CONFIRMED', 'FALSE_POSITIVE', 'REJECTED', 'ARCHIVED'));

-- 2. Update findings.confidence check constraint to support FIRM and CERTAIN
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_confidence_check;
ALTER TABLE findings ADD CONSTRAINT findings_confidence_check 
    CHECK (confidence IN ('TENTATIVE', 'FIRM', 'CONFIRMED', 'CERTAIN'));

-- 3. Enforce mandatory rejection reason when status is REJECTED
ALTER TABLE findings ADD CONSTRAINT chk_findings_rejection_reason 
    CHECK (status <> 'REJECTED' OR (rejection_reason IS NOT NULL AND length(trim(rejection_reason)) > 0));
