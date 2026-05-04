package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/sbom-io/api/internal/db"
)

// GetDashboardMetrics handles GET /api/dashboard/metrics.
func (h *Scans) GetDashboardMetrics(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	ctx := c.UserContext()
	m, err := db.GetDashboardMetrics(ctx, h.DB, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	recent := make([]fiber.Map, 0, len(m.RecentScans))
	for _, r := range m.RecentScans {
		recent = append(recent, fiber.Map{
			"id":          r.ID,
			"project_id":  r.ProjectID,
			"status":      r.Status,
			"created_at":  r.CreatedAt,
			"project_name": r.ProjectName,
			"github_url":  r.GithubURL,
		})
	}

	return c.JSON(fiber.Map{
		"total_projects":  m.TotalProjects,
		"total_scans":     m.TotalScans,
		"critical_cves":   m.CriticalCVEs,
		"clean_projects":  m.CleanProjects,
		"recent_scans":    recent,
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
	})
}
