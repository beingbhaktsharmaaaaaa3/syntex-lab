-- Run this once against your running database to fix the submit error
-- docker exec syntex_db psql -U syntex_admin -d syntex_db -f /tmp/migrate-reports.sql

ALTER TABLE reports ADD COLUMN IF NOT EXISTS affected_asset     VARCHAR(200);
ALTER TABLE reports ADD COLUMN IF NOT EXISTS flag_slug          VARCHAR(100);
ALTER TABLE reports ADD COLUMN IF NOT EXISTS flag_submitted     TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS flag_valid         BOOLEAN;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS flag_verified      BOOLEAN DEFAULT false;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS vuln_slug          VARCHAR(100);
ALTER TABLE reports ADD COLUMN IF NOT EXISTS points_awarded     INTEGER DEFAULT 0;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS first_blood        BOOLEAN DEFAULT false;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS verified_at        TIMESTAMP;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS validation_message TEXT;

-- Also patch vuln_flags found_at column referenced in program.js
ALTER TABLE user_flags ADD COLUMN IF NOT EXISTS found_at TIMESTAMP DEFAULT NOW();

SELECT 'Migration complete — reports table patched' AS status;
