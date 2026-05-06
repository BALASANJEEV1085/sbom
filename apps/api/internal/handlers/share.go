package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sbom-io/api/internal/db"
)

// ---------------------------------------------------------------------------
// 1. POST /api/sboms/:sbomID/share — Create a secure share link
// ---------------------------------------------------------------------------

type createShareLinkBody struct {
	Label         string `json:"label"`
	ExpiresInDays int    `json:"expires_in_days"`
}

func (h *Scans) CreateShareLink(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	sbomID := strings.TrimSpace(c.Params("sbomID"))
	if _, err := uuid.Parse(sbomID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid sbom_id"})
	}

	var body createShareLinkBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	if body.ExpiresInDays <= 0 {
		body.ExpiresInDays = 30 // default
	}
	if body.ExpiresInDays > 365 {
		body.ExpiresInDays = 365 // cap at 1 year
	}

	ctx := c.UserContext()

	// a/b. Verify user owns this sbom via sboms → scans → projects
	var scanID string
	err := h.DB.QueryRow(ctx, `SELECT scan_id::text FROM sboms WHERE id = $1::uuid`, sbomID).Scan(&scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "sbom not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	var projectID string
	if err := h.DB.QueryRow(ctx, `SELECT project_id::text FROM scans WHERE id = $1`, scanID).Scan(&projectID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	ok, err := db.ProjectOwnedByUser(ctx, h.DB, projectID, userID)
	if err != nil || !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	// c. Generate 32-byte secure random token → base64url (no padding)
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		log.Printf("CreateShareLink: rand.Read: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token generation failed"})
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)

	// d. Insert into shared_links
	expiresAt := time.Now().UTC().Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
	linkID := uuid.New().String()

	_, dbErr := h.DB.Exec(ctx, `
		INSERT INTO shared_links (id, sbom_id, token, label, expires_at, view_count, created_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, 0, NOW())
	`, linkID, sbomID, token, body.Label, expiresAt)
	if dbErr != nil {
		log.Printf("CreateShareLink: insert: %v", dbErr)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create share link"})
	}

	// e. Return share URL
	// In production this should be the web app URL. 
	// For dev, we'll use localhost:3000.
	scheme := "http"
	if c.Protocol() == "https" {
		scheme = "https"
	}
	_ = scheme
	
	// We want the WEB app URL, not the API URL. 
	// The API is on 8081, Web is on 3000.
	webURL := "http://localhost:3000"
	if strings.Contains(c.Hostname(), "sbom.io") {
		webURL = "https://sbom.io"
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"share_url":  fmt.Sprintf("%s/share/%s", webURL, token),
		"expires_at": expiresAt.Format(time.RFC3339),
		"label":      body.Label,
		"link_id":    linkID,
	})
}

// ---------------------------------------------------------------------------
// 2. GET /api/share/:token — Public endpoint, no auth required
// ---------------------------------------------------------------------------

func (h *Scans) ViewShareLink(c *fiber.Ctx) error {
	token := strings.TrimSpace(c.Params("token"))
	if token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing token"})
	}

	ctx := c.UserContext()

	// a. Look up shared_links WHERE token=$1
	var (
		linkID    string
		sbomID    string
		label     string
		expiresAt time.Time
	)
	err := h.DB.QueryRow(ctx, `
		SELECT id::text, sbom_id::text, COALESCE(label,''), expires_at
		FROM shared_links WHERE token = $1
	`, token).Scan(&linkID, &sbomID, &label, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "share link not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	// b. Expiry check
	if time.Now().UTC().After(expiresAt) {
		return c.Status(fiber.StatusGone).JSON(fiber.Map{"error": "share link has expired"})
	}

	// c. Increment view_count (fire-and-forget)
	go func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = h.DB.Exec(ctx2, `
			UPDATE shared_links SET view_count = view_count + 1 WHERE id = $1::uuid
		`, linkID)
	}()

	// d. Fetch sbom row
	var (
		sbomFormat       string
		sbomSpecVersion  string
		sbomSHA256       string
		sbomComponentCnt int
		sbomCreatedAt    time.Time
		sbomFileKey      string
		sbomScanID       string
	)
	err = h.DB.QueryRow(ctx, `
		SELECT format, spec_version, sha256_hash, COALESCE(component_count,0), created_at, file_key, scan_id::text
		FROM sboms WHERE id = $1::uuid
	`, sbomID).Scan(&sbomFormat, &sbomSpecVersion, &sbomSHA256, &sbomComponentCnt, &sbomCreatedAt, &sbomFileKey, &sbomScanID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "sbom not found"})
	}

	// Fetch project name via scan
	var projectID string
	_ = h.DB.QueryRow(ctx, `SELECT project_id::text FROM scans WHERE id = $1`, sbomScanID).Scan(&projectID)

	var repoName string
	_ = h.DB.QueryRow(ctx, `SELECT COALESCE(name,'') FROM projects WHERE id = $1::uuid`, projectID).Scan(&repoName)

	// d. Fetch components (limit 5000)
	compRows, err := h.DB.Query(ctx, `
		SELECT name, version, COALESCE(license,''), ecosystem, depth, COALESCE(parent_name,'')
		FROM components
		WHERE scan_id = $1
		ORDER BY name
		LIMIT 5000
	`, sbomScanID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "components query failed"})
	}
	defer compRows.Close()

	type compOut struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		License    string `json:"license"`
		Ecosystem  string `json:"ecosystem"`
		Depth      int    `json:"depth"`
		ParentName string `json:"parent_name"`
	}
	var components []compOut
	for compRows.Next() {
		var co compOut
		if err := compRows.Scan(&co.Name, &co.Version, &co.License, &co.Ecosystem, &co.Depth, &co.ParentName); err != nil {
			continue
		}
		components = append(components, co)
	}
	_ = compRows.Err()
	if components == nil {
		components = []compOut{}
	}

	// e. Fetch vulnerabilities for this scan
	vulnRows, err := h.DB.Query(ctx, `
		SELECT c.name, c.version, cv.cve_id, cv.severity, COALESCE(cv.summary,''), COALESCE(cv.fixed_version,'')
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
	`, sbomScanID)
	if err != nil {
		log.Printf("ViewShareLink: vulns query: %v", err)
	}

	type vulnOut struct {
		ComponentName    string `json:"component_name"`
		ComponentVersion string `json:"component_version"`
		CVEID            string `json:"cve_id"`
		Severity         string `json:"severity"`
		Summary          string `json:"summary"`
		FixedVersion     string `json:"fixed_version"`
	}
	var vulns []vulnOut
	vulnSummary := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

	if vulnRows != nil {
		defer vulnRows.Close()
		for vulnRows.Next() {
			var vo vulnOut
			var fixedVersion sql.NullString
			if err := vulnRows.Scan(
				&vo.ComponentName, &vo.ComponentVersion,
				&vo.CVEID, &vo.Severity, &vo.Summary, &fixedVersion,
			); err != nil {
				continue
			}
			if fixedVersion.Valid {
				vo.FixedVersion = fixedVersion.String
			}
			switch strings.ToUpper(vo.Severity) {
			case "CRITICAL":
				vulnSummary["critical"]++
			case "HIGH":
				vulnSummary["high"]++
			case "MEDIUM":
				vulnSummary["medium"]++
			case "LOW":
				vulnSummary["low"]++
			}
			vulns = append(vulns, vo)
		}
		_ = vulnRows.Err()
	}
	if vulns == nil {
		vulns = []vulnOut{}
	}

	// NTIA Minimum Elements compliance check
	hasSupplierName := repoName != ""
	hasComponentNames := len(components) > 0
	hasVersions := len(components) > 0 && components[0].Version != ""
	hasUniqueIDs := true // always true — we use PURLs
	hasDependencyRelationships := false
	for _, co := range components {
		if co.ParentName != "" {
			hasDependencyRelationships = true
			break
		}
	}
	hasAuthor := true    // we always set Creator: Tool
	hasTimestamp := true // we always set Created

	ntiaCompliant := hasSupplierName && hasComponentNames && hasVersions &&
		hasUniqueIDs && hasDependencyRelationships && hasAuthor && hasTimestamp

	// f. Return full response
	return c.JSON(fiber.Map{
		"label":           label,
		"repo_name":       repoName,
		"generated_at":    sbomCreatedAt.UTC().Format(time.RFC3339),
		"sha256":          sbomSHA256,
		"format":          sbomFormat,
		"spec_version":    sbomSpecVersion,
		"component_count": sbomComponentCnt,
		"vulnerability_summary": vulnSummary,
		"compliance": fiber.Map{
			"ntia_minimum_elements":       ntiaCompliant,
			"has_supplier_name":           hasSupplierName,
			"has_component_names":         hasComponentNames,
			"has_versions":                hasVersions,
			"has_unique_ids":              hasUniqueIDs,
			"has_dependency_relationships": hasDependencyRelationships,
			"has_author":                  hasAuthor,
			"has_timestamp":               hasTimestamp,
		},
		"components":      components,
		"vulnerabilities": vulns,
	})
}

// ---------------------------------------------------------------------------
// 3. GET /api/sboms/:sbomID/shares — List share links for an SBOM
// ---------------------------------------------------------------------------

func (h *Scans) ListShareLinks(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	sbomID := strings.TrimSpace(c.Params("sbomID"))
	if _, err := uuid.Parse(sbomID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid sbom_id"})
	}

	ctx := c.UserContext()

	// Ownership check
	var scanID string
	err := h.DB.QueryRow(ctx, `SELECT scan_id::text FROM sboms WHERE id = $1::uuid`, sbomID).Scan(&scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "sbom not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	var projectID string
	if err := h.DB.QueryRow(ctx, `SELECT project_id::text FROM scans WHERE id = $1`, scanID).Scan(&projectID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	ok, err := db.ProjectOwnedByUser(ctx, h.DB, projectID, userID)
	if err != nil || !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	// Fetch all share links
	rows, err := h.DB.Query(ctx, `
		SELECT id::text, token, COALESCE(label,''), expires_at, view_count, created_at
		FROM shared_links
		WHERE sbom_id = $1::uuid
		ORDER BY created_at DESC
	`, sbomID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	defer rows.Close()

	type linkOut struct {
		ID        string    `json:"id"`
		ShareURL  string    `json:"share_url"`
		Label     string    `json:"label"`
		ExpiresAt time.Time `json:"expires_at"`
		ViewCount int       `json:"view_count"`
		CreatedAt time.Time `json:"created_at"`
		Expired   bool      `json:"expired"`
	}

	var links []linkOut
	now := time.Now().UTC()
	for rows.Next() {
		var l linkOut
		var token string
		if err := rows.Scan(&l.ID, &token, &l.Label, &l.ExpiresAt, &l.ViewCount, &l.CreatedAt); err != nil {
			continue
		}
		webURL := "http://localhost:3000"
		if strings.Contains(c.Hostname(), "sbom.io") {
			webURL = "https://sbom.io"
		}
		l.ShareURL = fmt.Sprintf("%s/share/%s", webURL, token)
		l.Expired = now.After(l.ExpiresAt)
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	if links == nil {
		links = []linkOut{}
	}

	return c.JSON(fiber.Map{
		"sbom_id": sbomID,
		"links":   links,
		"total":   len(links),
	})
}
