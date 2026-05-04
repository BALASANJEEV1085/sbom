package handlers

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/sbom-io/api/internal/db"
	gh "github.com/sbom-io/api/internal/github"
)

type createProjectBody struct {
	GithubURL string `json:"github_url"`
	Name      string `json:"name"`
}

// CreateProject handles POST /api/projects.
func (h *Scans) CreateProject(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	var body createProjectBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	body.GithubURL = strings.TrimSpace(body.GithubURL)
	body.Name = strings.TrimSpace(body.Name)
	if body.GithubURL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "github_url is required"})
	}
	if _, _, err := gh.ParseRepoURL(body.GithubURL); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid github_url: " + err.Error()})
	}
	if body.Name == "" {
		owner, repo, err := gh.ParseRepoURL(body.GithubURL)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid github_url"})
		}
		body.Name = owner + "/" + repo
	}

	ctx := c.UserContext()
	id, err := db.CreateProject(ctx, h.DB, userID, body.Name, body.GithubURL)
	if err != nil {
		log.Printf("CreateProject error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create project"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":         id,
		"name":       body.Name,
		"github_url": body.GithubURL,
	})
}

// ListProjects handles GET /api/projects.
func (h *Scans) ListProjects(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	ctx := c.UserContext()
	list, err := db.ListProjectsByUser(ctx, h.DB, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	out := make([]fiber.Map, 0, len(list))
	for _, p := range list {
		out = append(out, fiber.Map{
			"id":         p.ID,
			"name":       p.Name,
			"github_url": p.GithubURL,
			"created_at": p.CreatedAt,
		})
	}

	return c.JSON(fiber.Map{"projects": out, "total": len(out)})
}
