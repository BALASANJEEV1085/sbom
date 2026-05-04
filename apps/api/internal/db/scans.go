// Package db persists scans and SBOM components to PostgreSQL via pgx/v5.
//
//	go get github.com/jackc/pgx/v5
package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sbom-io/api/internal/scanner"
)

// Querier matches *pgxpool.Pool and pgx.Tx for scan/component operations.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const componentInsertBatch = 500

// Scan is a row from the scans table.
type Scan struct {
	ID        string
	ProjectID string
	Status    string
	CreatedAt time.Time
}

// Component is a row from the components table.
type Component struct {
	ID          string
	ScanID      string
	Name        string
	Version     string
	VersionSpec string
	License     string
	Ecosystem   string
	Depth       int
	ParentName  string
	CreatedAt   time.Time
}

// CreateScan inserts a new scan with status "running" and returns its id.
func CreateScan(ctx context.Context, db Querier, projectID string) (scanID string, err error) {
	id := uuid.New()
	err = db.QueryRow(ctx, `
		INSERT INTO scans (id, project_id, status, created_at)
		VALUES ($1, $2, 'running', NOW())
		RETURNING id::text
	`, id, projectID).Scan(&scanID)
	if err != nil {
		return "", fmt.Errorf("create scan: %w", err)
	}
	return scanID, nil
}

// UpdateScanStatus sets scans.status to one of: running, done, failed.
func UpdateScanStatus(ctx context.Context, db Querier, scanID, status string) error {
	switch status {
	case "running", "done", "failed":
	default:
		return fmt.Errorf("invalid scan status %q (want running|done|failed)", status)
	}
	tag, err := db.Exec(ctx, `
		UPDATE scans SET status = $1 WHERE id = $2::uuid
	`, status, scanID)
	if err != nil {
		return fmt.Errorf("update scan status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("update scan status: no scan with id %s", scanID)
	}
	return nil
}

// SaveComponents bulk-inserts packages as components in batches of 500 rows per INSERT.
func SaveComponents(ctx context.Context, db Querier, scanID string, packages []scanner.Package) error {
	if len(packages) == 0 {
		return nil
	}

	for start := 0; start < len(packages); start += componentInsertBatch {
		end := min(start+componentInsertBatch, len(packages))
		batch := packages[start:end]

		var sb strings.Builder
		sb.WriteString(`
			INSERT INTO components (
				id, scan_id, name, version, version_spec, license, ecosystem, depth, parent_name, created_at
			) VALUES `)

		args := make([]any, 0, len(batch)*9)
		ph := 1
		for i, p := range batch {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "($%d::uuid, $%d::uuid, $%d, $%d, $%d, $%d, $%d, $%d, $%d, NOW())",
				ph, ph+1, ph+2, ph+3, ph+4, ph+5, ph+6, ph+7, ph+8)
			ph += 9
			args = append(args,
				uuid.New(),
				scanID,
				p.Name,
				p.Version,
				p.VersionSpec,
				p.License,
				p.Ecosystem,
				p.Depth,
				p.ParentName,
			)
		}

		if _, err := db.Exec(ctx, sb.String(), args...); err != nil {
			return fmt.Errorf("save components batch [%d:%d]: %w", start, end, err)
		}
	}
	return nil
}

// GetScanWithComponents loads the scan and all related components using a single joined query.
func GetScanWithComponents(ctx context.Context, db Querier, scanID string) (scan Scan, components []Component, err error) {
	rows, err := db.Query(ctx, `
		SELECT
			s.id::text, s.project_id::text, s.status, s.created_at,
			c.id::text, c.scan_id::text, c.name, c.version, c.version_spec, c.license, c.ecosystem, c.depth, c.parent_name, c.created_at
		FROM scans s
		LEFT JOIN components c ON c.scan_id = s.id
		WHERE s.id = $1::uuid
		ORDER BY c.name NULLS LAST
	`, scanID)
	if err != nil {
		return Scan{}, nil, fmt.Errorf("get scan with components: %w", err)
	}
	defer rows.Close()

	var sawScan bool
	for rows.Next() {
		var s Scan
		var cID, cScanID sql.NullString
		var cName, cVersion, cVersionSpec, cLicense, cEcosystem, cParent sql.NullString
		var cDepth sql.NullInt32
		var cCreated sql.NullTime

		if err := rows.Scan(
			&s.ID, &s.ProjectID, &s.Status, &s.CreatedAt,
			&cID, &cScanID, &cName, &cVersion, &cVersionSpec, &cLicense, &cEcosystem, &cDepth, &cParent, &cCreated,
		); err != nil {
			return Scan{}, nil, fmt.Errorf("scan row: %w", err)
		}
		if !sawScan {
			scan = s
			sawScan = true
		}
		if cID.Valid {
			components = append(components, Component{
				ID:          cID.String,
				ScanID:      cScanID.String,
				Name:        cName.String,
				Version:     cVersion.String,
				VersionSpec: cVersionSpec.String,
				License:     cLicense.String,
				Ecosystem:   cEcosystem.String,
				Depth:       int(cDepth.Int32),
				ParentName:  cParent.String,
				CreatedAt:   cCreated.Time,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return Scan{}, nil, fmt.Errorf("iterate rows: %w", err)
	}
	if !sawScan {
		return Scan{}, nil, fmt.Errorf("get scan with components: %w", pgx.ErrNoRows)
	}
	return scan, components, nil
}

// ProjectOwnedByUser reports whether a row exists in projects with the given owner.
// Expected schema: projects (id UUID PK, user_id UUID).
func ProjectOwnedByUser(ctx context.Context, db Querier, projectID, userID string) (ok bool, err error) {
	err = db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM projects WHERE id = $1::uuid AND user_id = $2::uuid
		)
	`, projectID, userID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("project ownership: %w", err)
	}
	return ok, nil
}

// ListScansForProject returns scans for a project ordered by newest first.
func ListScansForProject(ctx context.Context, db Querier, projectID string) ([]Scan, error) {
	rows, err := db.Query(ctx, `
		SELECT id::text, project_id::text, status, created_at
		FROM scans
		WHERE project_id = $1::uuid
		ORDER BY created_at DESC
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.Status, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan list row: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list scans iterate: %w", err)
	}
	return out, nil
}
