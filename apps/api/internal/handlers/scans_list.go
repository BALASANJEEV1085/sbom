package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/sbom-io/api/internal/db"
)

// ListAllScans handles GET /api/scans (must be registered before GET /api/scans/:scanID).
func (h *Scans) ListAllScans(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	ctx := c.UserContext()
	rows, err := db.ListUserScans(ctx, h.DB, userID, 200)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	out := make([]fiber.Map, 0, len(rows))
	for _, r := range rows {
		out = append(out, fiber.Map{
			"id":           r.ID,
			"project_id":   r.ProjectID,
			"status":       r.Status,
			"created_at":   r.CreatedAt,
			"project_name": r.ProjectName,
			"github_url":   r.GithubURL,
		})
	}

	return c.JSON(fiber.Map{"scans": out, "total": len(out)})
}
