package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Project is a row in the projects table.
type Project struct {
	ID        string
	UserID    string
	Name      string
	GithubURL string
	CreatedAt time.Time
}

// CreateProject inserts a project owned by userID and returns its id.
func CreateProject(ctx context.Context, db Querier, userID, name, githubURL string) (projectID string, err error) {
	id := uuid.New()
	err = db.QueryRow(ctx, `
		INSERT INTO projects (id, user_id, name, github_url, created_at)
		VALUES ($1, $2::uuid, $3, $4, NOW())
		RETURNING id::text
	`, id, userID, name, githubURL).Scan(&projectID)
	if err != nil {
		return "", fmt.Errorf("create project: %w", err)
	}
	return projectID, nil
}

// ListProjectsByUser returns projects for a user, newest first.
func ListProjectsByUser(ctx context.Context, db Querier, userID string) ([]Project, error) {
	rows, err := db.Query(ctx, `
		SELECT id::text, user_id::text, COALESCE(name, ''), COALESCE(github_url, ''), created_at
		FROM projects
		WHERE user_id = $1::uuid
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.GithubURL, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("list projects row: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list projects iterate: %w", err)
	}
	return out, nil
}

// GetProjectForUser returns name and github_url if the project exists and belongs to userID.
func GetProjectForUser(ctx context.Context, db Querier, projectID, userID string) (name, githubURL string, err error) {
	err = db.QueryRow(ctx, `
		SELECT COALESCE(name, ''), COALESCE(github_url, '')
		FROM projects
		WHERE id = $1::uuid AND user_id = $2::uuid
	`, projectID, userID).Scan(&name, &githubURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", fmt.Errorf("project not found: %w", err)
		}
		return "", "", fmt.Errorf("get project: %w", err)
	}
	return name, githubURL, nil
}

// UserScanRow is a scan joined with its parent project for dashboard lists.
type UserScanRow struct {
	Scan
	ProjectName     string
	GithubURL       string
	ComplianceScore *int
	NTIACompliant   *bool
}

// ListUserScans returns scans across all projects owned by the user.
func ListUserScans(ctx context.Context, db Querier, userID string, limit int) ([]UserScanRow, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	rows, err := db.Query(ctx, `
		SELECT s.id::text, s.project_id::text, s.status, s.created_at,
		       COALESCE(p.name, ''), COALESCE(p.github_url, ''),
		       s.compliance_score, s.ntia_compliant
		FROM scans s
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid
		ORDER BY s.created_at DESC
		LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list user scans: %w", err)
	}
	defer rows.Close()

	var out []UserScanRow
	for rows.Next() {
		var row UserScanRow
		if err := rows.Scan(
			&row.ID, &row.ProjectID, &row.Status, &row.CreatedAt,
			&row.ProjectName, &row.GithubURL,
			&row.ComplianceScore, &row.NTIACompliant,
		); err != nil {
			return nil, fmt.Errorf("list user scans row: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user scans iterate: %w", err)
	}
	return out, nil
}

// DashboardMetrics holds home dashboard counters.
type DashboardMetrics struct {
	TotalProjects  int64
	TotalScans     int64
	CriticalCVEs   int64
	CleanProjects  int64
	RecentScans    []UserScanRow
}

func isUndefinedRelation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// GetDashboardMetrics loads aggregate counts for the signed-in user.
// If the vulnerabilities table is missing (Day 2 bootstrap), critical CVE count is 0 and clean_projects equals total_projects.
func GetDashboardMetrics(ctx context.Context, db Querier, userID string) (DashboardMetrics, error) {
	var m DashboardMetrics

	err := db.QueryRow(ctx, `SELECT COUNT(*)::bigint FROM projects WHERE user_id = $1::uuid`, userID).Scan(&m.TotalProjects)
	if err != nil {
		return m, fmt.Errorf("count projects: %w", err)
	}

	err = db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM scans s
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid
	`, userID).Scan(&m.TotalScans)
	if err != nil {
		return m, fmt.Errorf("count scans: %w", err)
	}

	err = db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM vulnerabilities v
		INNER JOIN scans s ON s.id = v.scan_id
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid AND lower(v.severity) IN ('critical', 'crit')
	`, userID).Scan(&m.CriticalCVEs)
	if err != nil {
		if isUndefinedRelation(err) {
			m.CriticalCVEs = 0
		} else {
			return m, fmt.Errorf("count critical cves: %w", err)
		}
	}

	err = db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM projects p
		WHERE p.user_id = $1::uuid
		AND NOT EXISTS (
			SELECT 1
			FROM scans s
			INNER JOIN vulnerabilities v ON v.scan_id = s.id
			WHERE s.project_id = p.id
			AND lower(v.severity) IN ('critical', 'crit')
		)
	`, userID).Scan(&m.CleanProjects)
	if err != nil {
		if isUndefinedRelation(err) {
			m.CleanProjects = m.TotalProjects
		} else {
			return m, fmt.Errorf("count clean projects: %w", err)
		}
	}

	recent, err := ListUserScans(ctx, db, userID, 8)
	if err != nil {
		return m, err
	}
	m.RecentScans = recent
	return m, nil
}
