-- 001_initial.sql  (idempotent — safe to re-run)
-- Creates all tables the Go API needs, or patches existing ones.

-- ── projects ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL,
    name       TEXT,
    github_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS user_id    UUID,
    ADD COLUMN IF NOT EXISTS name       TEXT,
    ADD COLUMN IF NOT EXISTS github_url TEXT,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_projects_user ON projects (user_id);

-- ── scans ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL,
    status     TEXT NOT NULL DEFAULT 'running',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS project_id UUID,
    ADD COLUMN IF NOT EXISTS status     TEXT NOT NULL DEFAULT 'running',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans (project_id);

-- ── components ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS components (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    version_spec TEXT NOT NULL DEFAULT '',
    license      TEXT NOT NULL DEFAULT '',
    ecosystem    TEXT NOT NULL DEFAULT 'npm',
    depth        INT  NOT NULL DEFAULT 0,
    parent_name  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE components
    ADD COLUMN IF NOT EXISTS scan_id      UUID,
    ADD COLUMN IF NOT EXISTS name         TEXT,
    ADD COLUMN IF NOT EXISTS version      TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS version_spec TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS license      TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ecosystem    TEXT NOT NULL DEFAULT 'npm',
    ADD COLUMN IF NOT EXISTS depth        INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS parent_name  TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_components_scan ON components (scan_id);

-- ── vulnerabilities ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id    UUID NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'unknown',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS scan_id    UUID,
    ADD COLUMN IF NOT EXISTS severity   TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan ON vulnerabilities (scan_id);

-- ── RLS ───────────────────────────────────────────────────────────────────────
ALTER TABLE projects        ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans           ENABLE ROW LEVEL SECURITY;
ALTER TABLE components      ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS projects_owner    ON projects;
DROP POLICY IF EXISTS scans_owner       ON scans;
DROP POLICY IF EXISTS components_owner  ON components;
DROP POLICY IF EXISTS vulnerabilities_owner ON vulnerabilities;

CREATE POLICY projects_owner ON projects
    USING      (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

CREATE POLICY scans_owner ON scans
    USING (EXISTS (
        SELECT 1 FROM projects p
        WHERE p.id = scans.project_id AND p.user_id = auth.uid()
    ));

CREATE POLICY components_owner ON components
    USING (EXISTS (
        SELECT 1 FROM scans s
        JOIN projects p ON p.id = s.project_id
        WHERE s.id = components.scan_id AND p.user_id = auth.uid()
    ));

CREATE POLICY vulnerabilities_owner ON vulnerabilities
    USING (EXISTS (
        SELECT 1 FROM scans s
        JOIN projects p ON p.id = s.project_id
        WHERE s.id = vulnerabilities.scan_id AND p.user_id = auth.uid()
    ));
