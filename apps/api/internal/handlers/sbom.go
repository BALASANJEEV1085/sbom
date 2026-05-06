package handlers

import (
	"context"
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
	"github.com/sbom-io/api/internal/sbom"
	"github.com/sbom-io/api/internal/scanner"
	"github.com/sbom-io/api/internal/storage"
	"github.com/sbom-io/api/internal/vuln"
)

// generateSBOMBody is the JSON request body for POST /api/scans/:scanID/sbom.
type generateSBOMBody struct {
	Format string `json:"format"` // "cyclonedx" or "spdx"
}

// GenerateSBOM handles POST /api/scans/:scanID/sbom.
// It generates the SBOM bytes, returns them directly as base64 in the JSON
// response (so the frontend can download immediately), and attempts an S3
// upload in the background as best-effort (never blocks the response).
func (h *Scans) GenerateSBOM(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	scanID := strings.TrimSpace(c.Params("scanID"))
	if _, err := uuid.Parse(scanID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid scan_id"})
	}

	var body generateSBOMBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	body.Format = strings.ToLower(strings.TrimSpace(body.Format))
	if body.Format != "cyclonedx" && body.Format != "spdx" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": `format must be "cyclonedx" or "spdx"`,
		})
	}

	ctx := c.UserContext()

	// a. Fetch scan + components from DB
	scan, dbComponents, err := db.GetScanWithComponents(ctx, h.DB, scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scan not found"})
		}
		log.Printf("GenerateSBOM: GetScanWithComponents: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	// Ownership check
	ok, err := db.ProjectOwnedByUser(ctx, h.DB, scan.ProjectID, userID)
	if err != nil || !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	// Fetch vulnerabilities (best-effort)
	var vulns []vuln.ComponentVuln
	if vulns, err = vuln.MatchVulnerabilities(ctx, h.DB, scanID); err != nil {
		log.Printf("GenerateSBOM: MatchVulnerabilities: %v", err)
		vulns = nil
	}

	// b. Build ScanInfo
	pName, pURL, _ := db.GetProjectForUser(ctx, h.DB, scan.ProjectID, userID)
	scanInfo := sbom.ScanInfo{
		ID:        scan.ID,
		RepoName:  pName,
		RepoURL:   pURL,
		Ecosystem: ecosystemFromComponents(dbComponents),
	}

	// c/d. Generate SBOM bytes
	var fileBytes []byte
	var hashHex, specVersion, contentType, fileExt string
	pkgs := dbComponentsToPackages(dbComponents)

	switch body.Format {
	case "cyclonedx":
		fileBytes, hashHex, err = sbom.GenerateCycloneDX(scanInfo, pkgs, vulns)
		specVersion = "1.5"
		contentType = "application/json"
		fileExt = "json"
	case "spdx":
		fileBytes, hashHex, err = sbom.GenerateSPDX(scanInfo, pkgs)
		specVersion = "SPDX-2.3"
		contentType = "text/plain"
		fileExt = "spdx"
	}
	if err != nil {
		log.Printf("GenerateSBOM: generate %s: %v", body.Format, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "sbom generation failed"})
	}

	// e. S3 upload — best-effort in background, never blocks the response
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	fileKey := fmt.Sprintf("sboms/%s/%s-%s.%s", scanID, body.Format, timestamp, fileExt)
	sbomID := uuid.New().String()

	fileBytesCopy := make([]byte, len(fileBytes))
	copy(fileBytesCopy, fileBytes)
	go func() {
		s3Client, s3Err := storage.NewStorageClient()
		if s3Err != nil {
			log.Printf("GenerateSBOM: NewStorageClient (bg): %v", s3Err)
			return
		}
		uploadCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if upErr := storage.UploadFile(uploadCtx, s3Client, fileKey, fileBytesCopy, contentType); upErr != nil {
			log.Printf("GenerateSBOM: bg upload: %v", upErr)
			return
		}
		log.Printf("GenerateSBOM: bg upload succeeded: %s", fileKey)
	}()

	// f. Save to sboms table (best-effort)
	_, dbErr := h.DB.Exec(ctx, `
		INSERT INTO sboms (id, scan_id, format, spec_version, file_key, file_size_bytes, sha256_hash, component_count, created_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, NOW())
	`, sbomID, scanID, body.Format, specVersion, fileKey, len(fileBytes), hashHex, len(dbComponents))
	if dbErr != nil {
		log.Printf("GenerateSBOM: insert sboms row: %v", dbErr)
	}

	// g. Return file bytes as base64 — frontend creates a Blob download URL.
	//    This works even when S3 is misconfigured; no presigned URL needed.
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"sbom_id":         sbomID,
		"sha256":          hashHex,
		"download_url":    "", // populated later once S3 upload is confirmed
		"file_data":       base64.StdEncoding.EncodeToString(fileBytes),
		"content_type":    contentType,
		"file_name":       fmt.Sprintf("sbom-%s-%s.%s", body.Format, scanID[:8], fileExt),
		"component_count": len(dbComponents),
	})
}

// DownloadSBOM handles GET /api/sboms/:sbomID/download.
func (h *Scans) DownloadSBOM(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	sbomID := strings.TrimSpace(c.Params("sbomID"))
	if _, err := uuid.Parse(sbomID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid sbom_id"})
	}

	ctx := c.UserContext()

	var fileKey, scanID string
	err := h.DB.QueryRow(ctx, `SELECT file_key, scan_id::text FROM sboms WHERE id = $1::uuid`, sbomID).Scan(&fileKey, &scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "sbom not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	var projectID string
	if err := h.DB.QueryRow(ctx, "SELECT project_id FROM scans WHERE id = $1", scanID).Scan(&projectID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	ok, err := db.ProjectOwnedByUser(ctx, h.DB, projectID, userID)
	if err != nil || !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	s3Client, err := storage.NewStorageClient()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "storage not configured"})
	}

	presignCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	downloadURL, err := storage.GetPresignedURL(presignCtx, s3Client, fileKey, time.Hour)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not generate download URL"})
	}

	return c.Redirect(downloadURL, fiber.StatusFound)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func dbComponentsToPackages(components []db.Component) []scanner.Package {
	pkgs := make([]scanner.Package, 0, len(components))
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
	return pkgs
}

func ecosystemFromComponents(components []db.Component) string {
	for _, c := range components {
		if c.Ecosystem != "" {
			return c.Ecosystem
		}
	}
	return "unknown"
}
