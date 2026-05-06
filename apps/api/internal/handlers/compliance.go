package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sbom-io/api/internal/compliance"
	"github.com/sbom-io/api/internal/db"
)

// GetCompliance handles GET /api/scans/:scanID/compliance
func (h *Scans) GetCompliance(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	scanID := strings.TrimSpace(c.Params("scanID"))
	if _, err := uuid.Parse(scanID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid scan_id"})
	}

	ctx := c.UserContext()

	// Verify ownership
	var projectID string
	err := h.DB.QueryRow(ctx, "SELECT project_id FROM scans WHERE id = $1", scanID).Scan(&projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scan not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	ok, err := db.ProjectOwnedByUser(ctx, h.DB, projectID, userID)
	if err != nil || !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	var detailJSON []byte
	var euCompliant bool
	err = h.DB.QueryRow(ctx, `
		SELECT compliance_detail, eu_cra_compliant 
		FROM scans WHERE id = $1
	`, scanID).Scan(&detailJSON, &euCompliant)
	
	if err != nil {
		// Try pointer scan if it was a different error, but mostly likely it's just NULL or missing
		var detailJSONPtr []byte
		var euCompliantPtr *bool
		err2 := h.DB.QueryRow(ctx, `
			SELECT compliance_detail, eu_cra_compliant 
			FROM scans WHERE id = $1
		`, scanID).Scan(&detailJSONPtr, &euCompliantPtr)
		
		if err2 != nil || detailJSONPtr == nil {
			return c.JSON(fiber.Map{
				"compliant":        false,
				"score":            0,
				"elements":         []interface{}{},
				"recommendations":  []string{},
				"eu_cra_compliant": false,
			})
		}
		detailJSON = detailJSONPtr
		if euCompliantPtr != nil {
			euCompliant = *euCompliantPtr
		}
	}

	var detail compliance.NTIAResult
	if len(detailJSON) > 0 {
		if err := json.Unmarshal(detailJSON, &detail); err != nil {
			log.Printf("GetCompliance: unmarshal error: %v", err)
		}
	}


	res := fiber.Map{
		"compliant":        detail.Compliant,
		"score":            detail.Score,
		"elements":         detail.Elements,
		"recommendations":  detail.Recommendations,
		"eu_cra_compliant": euCompliant,
	}
	return c.JSON(res)
}
