package db

import (
	"context"
	"fmt"
	"log"
	"time"
)

// DashboardScanRow is a rich scan row for the /dashboard/stats endpoint.
type DashboardScanRow struct {
	ID             string
	ProjectName    string
	Ecosystem      string
	Status         string
	ComponentCount int64
	CriticalCVEs   int64
	NTIAScore      *int
	CreatedAt      time.Time
}

// DashboardStats holds all aggregates for the stats endpoint.
type DashboardStats struct {
	TotalProjects      int64
	TotalScans         int64
	TotalComponents    int64
	CriticalCVEs       int64
	HighCVEs           int64
	MediumCVEs         int64
	LowCVEs            int64
	NTIACompliantScans int64
	NonCompliantScans  int64
	CleanProjects      int64
	RecentScans        []DashboardScanRow
}

// GetDashboardStats returns rich aggregate statistics for the signed-in user.
func GetDashboardStats(ctx context.Context, db Querier, userID string) (DashboardStats, error) {
	var s DashboardStats

	// 1. Project count
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*)::bigint FROM projects WHERE user_id = $1::uuid`,
		userID).Scan(&s.TotalProjects); err != nil {
		log.Printf("dashboard/stats: count projects: %v", err)
		return s, fmt.Errorf("count projects: %w", err)
	}

	// 2. Scan count
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM scans s
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid
	`, userID).Scan(&s.TotalScans); err != nil {
		log.Printf("dashboard/stats: count scans: %v", err)
		return s, fmt.Errorf("count scans: %w", err)
	}

	// 3. Total components
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM components c
		INNER JOIN scans s ON s.id = c.scan_id
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid
	`, userID).Scan(&s.TotalComponents); err != nil {
		log.Printf("dashboard/stats: count components: %v", err)
		return s, fmt.Errorf("count components: %w", err)
	}

	// 4. CVE counts by severity — guarded against missing table
	cveRows, cveErr := db.Query(ctx, `
		SELECT lower(cv.severity), COUNT(*)::bigint
		FROM component_vulnerabilities cv
		INNER JOIN components c ON c.id = cv.component_id
		INNER JOIN scans s ON s.id = c.scan_id
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid
		GROUP BY lower(cv.severity)
	`, userID)
	if cveErr != nil && !isUndefinedRelation(cveErr) {
		log.Printf("dashboard/stats: count cves: %v", cveErr)
		return s, fmt.Errorf("count cves: %w", cveErr)
	}
	if cveErr == nil {
		defer cveRows.Close()
		for cveRows.Next() {
			var sev string
			var cnt int64
			if scanErr := cveRows.Scan(&sev, &cnt); scanErr != nil {
				continue
			}
			switch sev {
			case "critical", "crit":
				s.CriticalCVEs += cnt
			case "high":
				s.HighCVEs += cnt
			case "medium", "moderate", "mod":
				s.MediumCVEs += cnt
			case "low":
				s.LowCVEs += cnt
			}
		}
	}

	// 5. NTIA compliant vs non-compliant (uses FILTER aggregate — safe, no extra table)
	if err := db.QueryRow(ctx, `
		SELECT
		  COALESCE(COUNT(*) FILTER (WHERE s.ntia_compliant = true), 0)::bigint,
		  COALESCE(COUNT(*) FILTER (WHERE s.ntia_compliant = false), 0)::bigint
		FROM scans s
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid AND s.status = 'done'
	`, userID).Scan(&s.NTIACompliantScans, &s.NonCompliantScans); err != nil {
		log.Printf("dashboard/stats: count ntia: %v", err)
		return s, fmt.Errorf("count ntia: %w", err)
	}

	// 6. Clean projects — gracefully falls back if vuln table missing
	cleanErr := db.QueryRow(ctx, `
		SELECT COUNT(*)::bigint
		FROM projects p
		WHERE p.user_id = $1::uuid
		AND NOT EXISTS (
			SELECT 1
			FROM scans sc
			INNER JOIN component_vulnerabilities cv ON cv.component_id IN (
				SELECT id FROM components WHERE scan_id = sc.id
			)
			WHERE sc.project_id = p.id AND lower(cv.severity) IN ('critical','crit')
		)
	`, userID).Scan(&s.CleanProjects)
	if cleanErr != nil {
		if isUndefinedRelation(cleanErr) {
			s.CleanProjects = s.TotalProjects
		} else {
			log.Printf("dashboard/stats: count clean projects: %v", cleanErr)
			return s, fmt.Errorf("count clean projects: %w", cleanErr)
		}
	}

	// 7. Recent scans (last 5) — no component_vulnerabilities subquery to stay safe
	scanRows, err := db.Query(ctx, `
		SELECT
		  s.id::text,
		  COALESCE(NULLIF(TRIM(p.name), ''), NULLIF(p.github_url, ''), 'unknown'),
		  s.status,
		  (SELECT COUNT(*) FROM components c WHERE c.scan_id = s.id)::bigint,
		  s.compliance_score,
		  s.created_at
		FROM scans s
		INNER JOIN projects p ON p.id = s.project_id
		WHERE p.user_id = $1::uuid
		ORDER BY s.created_at DESC
		LIMIT 5
	`, userID)
	if err != nil {
		log.Printf("dashboard/stats: recent scans: %v", err)
		return s, fmt.Errorf("recent scans: %w", err)
	}
	defer scanRows.Close()
	for scanRows.Next() {
		var r DashboardScanRow
		if scanErr := scanRows.Scan(
			&r.ID, &r.ProjectName, &r.Status,
			&r.ComponentCount, &r.NTIAScore, &r.CreatedAt,
		); scanErr != nil {
			log.Printf("dashboard/stats: scan row: %v", scanErr)
			continue
		}
		s.RecentScans = append(s.RecentScans, r)
	}

	log.Printf("dashboard/stats: projects=%d scans=%d components=%d recent=%d",
		s.TotalProjects, s.TotalScans, s.TotalComponents, len(s.RecentScans))
	return s, nil
}
