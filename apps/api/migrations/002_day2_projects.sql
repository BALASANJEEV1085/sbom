-- Day 2: project metadata, optional vulnerabilities for dashboard metrics.
-- Run against the same database as the API (e.g. psql "$DATABASE_URL" -f ...).

ALTER TABLE projects
	ADD COLUMN IF NOT EXISTS name TEXT,
	ADD COLUMN IF NOT EXISTS github_url TEXT;

CREATE TABLE IF NOT EXISTS vulnerabilities (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
	severity TEXT NOT NULL DEFAULT 'unknown',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities (scan_id);
