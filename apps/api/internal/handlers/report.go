package handlers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sbom-io/api/internal/compliance"
	"github.com/sbom-io/api/internal/db"
	gh "github.com/sbom-io/api/internal/github"
	"github.com/sbom-io/api/internal/report"
	"github.com/sbom-io/api/internal/scanner"
)

// DownloadPDFReport handles GET /api/scans/:scanID/report/pdf
func (h *Scans) DownloadPDFReport(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	scanID := strings.TrimSpace(c.Params("scanID"))
	if _, err := uuid.Parse(scanID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid scan_id"})
	}

	ctx := c.UserContext()

	// 1. Fetch scan + components
	scan, components, err := db.GetScanWithComponents(ctx, h.DB, scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scan not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	// Verify ownership
	ok, err := db.ProjectOwnedByUser(ctx, h.DB, scan.ProjectID, userID)
	if err != nil || !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	// Get project details to get RepoName and Ecosystem
	_, pURL, _ := db.GetProjectForUser(ctx, h.DB, scan.ProjectID, userID)
	owner, repo, err := gh.ParseRepoURL(pURL)
	repoName := "unknown"
	if err == nil {
		repoName = owner + "/" + repo
	}

	ecosystem := "unknown"
	if len(components) > 0 {
		ecosystem = components[0].Ecosystem
	}

	scanInfo := report.ScanInfo{
		ID:          scan.ID,
		RepoName:    repoName,
		RepoURL:     pURL,
		Ecosystem:   ecosystem,
		GeneratedAt: scan.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
	}

	// 2. Fetch Compliance NTIA
	var ntia compliance.NTIAResult
	err = h.DB.QueryRow(ctx, "SELECT compliance_detail FROM scans WHERE id = $1", scanID).Scan(&ntia)
	if err != nil {
		fmt.Printf("DEBUG: Error fetching compliance_detail for %s: %v\n", scanID, err)
	}

	// 3. Fetch vulnerabilities
	query := `
		SELECT 
			c.name, c.version, cv.cve_id, cv.severity, cv.summary
		FROM component_vulnerabilities cv
		JOIN components c ON c.id = cv.component_id
		WHERE c.scan_id = $1
		ORDER BY 
			CASE cv.severity
				WHEN 'CRITICAL' THEN 1
				WHEN 'HIGH' THEN 2
				WHEN 'MEDIUM' THEN 3
				WHEN 'LOW' THEN 4
				ELSE 5
			END
	`
	rows, err := h.DB.Query(ctx, query, scanID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch vulns"})
	}

	var topVulns []report.ReportVuln
	var vulnSummary report.VulnSummary

	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var v report.ReportVuln
			if err := rows.Scan(&v.Package, &v.Version, &v.CVEID, &v.Severity, &v.Summary); err != nil {
				continue
			}
			switch strings.ToUpper(v.Severity) {
			case "CRITICAL":
				vulnSummary.Critical++
			case "HIGH":
				vulnSummary.High++
			case "MEDIUM":
				vulnSummary.Medium++
			case "LOW":
				vulnSummary.Low++
			}
			if len(topVulns) < 20 {
				topVulns = append(topVulns, v)
			}
		}
	}

	// Re-map components from db.Component to scanner.Package
	var pkgs []scanner.Package
	for _, c := range components {
		pkgs = append(pkgs, scanner.Package{
			Name:        c.Name,
			Version:     c.Version,
			VersionSpec: c.VersionSpec,
			License:     c.License,
			Ecosystem:   c.Ecosystem,
			Depth:       c.Depth,
			ParentName:  c.ParentName,
		})
	}

	pdfBytes, err := report.GeneratePDFReport(scanInfo, pkgs, vulnSummary, topVulns, ntia)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate PDF: " + err.Error()})
	}

	c.Set("Content-Type", "application/pdf")
	filename := repo
	if filename == "" {
		filename = "project"
	}
	c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sbom-report-%s.pdf"`, filename))
	return c.Send(pdfBytes)
}
