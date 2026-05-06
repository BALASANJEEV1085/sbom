package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"

	gh "github.com/sbom-io/api/internal/github"
	"github.com/sbom-io/api/internal/handlers"
)

func main() {
	// Load .env from cwd (e.g. apps/api/.env) when present; missing file is OK.
	_ = godotenv.Load()

	app := fiber.New()
	app.Use(logger.New())

	// Browser dashboard calls this API from another origin (Next.js dev server).
	corsOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOW_ORIGINS"))
	if corsOrigins == "" {
		corsOrigins = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001"
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins:     corsOrigins,
		AllowMethods:     "GET,POST,HEAD,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization",
		AllowCredentials: false,
	}))

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status": "ok",
		})
	})

	// Lists files in a repo directory:
	// /github/files?repo_url=https://github.com/owner/repo&path=optional/dir
	app.Get("/github/files", func(c *fiber.Ctx) error {
		token := extractToken(c)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing github token (use Authorization: Bearer <token> or X-GitHub-Token)",
			})
		}

		repoURL := c.Query("repo_url")
		dirPath := c.Query("path")
		owner, repo, err := gh.ParseRepoURL(repoURL)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid repo_url: " + err.Error(),
			})
		}

		client := gh.NewClient(token)
		ctx, cancel := contextWithTimeout(c)
		defer cancel()

		files, err := client.ListFiles(ctx, owner, repo, dirPath)
		if err != nil {
			var rlErr *gh.RateLimitError
			if errors.As(err, &rlErr) {
				return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
					"error":      rlErr.Error(),
					"reset_time": rlErr.ResetTime,
				})
			}
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"owner": owner,
			"repo":  repo,
			"path":  dirPath,
			"files": files,
		})
	})

	// Fetches file bytes from a repo path and returns raw content.
	// /github/file?repo_url=https://github.com/owner/repo&path=path/to/file
	app.Get("/github/file", func(c *fiber.Ctx) error {
		token := extractToken(c)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing github token (use Authorization: Bearer <token> or X-GitHub-Token)",
			})
		}

		repoURL := c.Query("repo_url")
		filePath := c.Query("path")
		if strings.TrimSpace(filePath) == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "missing required query param: path",
			})
		}

		owner, repo, err := gh.ParseRepoURL(repoURL)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid repo_url: " + err.Error(),
			})
		}

		client := gh.NewClient(token)
		ctx, cancel := contextWithTimeout(c)
		defer cancel()

		content, err := client.FetchFile(ctx, owner, repo, filePath)
		if err != nil {
			var rlErr *gh.RateLimitError
			if errors.As(err, &rlErr) {
				return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
					"error":      rlErr.Error(),
					"reset_time": rlErr.ResetTime,
				})
			}
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		c.Set(fiber.HeaderContentType, "application/octet-stream")
		return c.Send(content)
	})

	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	jwtSecret := strings.TrimSpace(os.Getenv("SUPABASE_JWT_SECRET"))
	if dbURL != "" && jwtSecret != "" {
		pool, err := pgxpool.New(context.Background(), dbURL)
		if err != nil {
			log.Fatalf("database pool: %v", err)
		}
		defer pool.Close()

		var rdb *redis.Client
		if redisURL := strings.TrimSpace(os.Getenv("REDIS_URL")); redisURL != "" {
			opt, err := redis.ParseURL(redisURL)
			if err != nil {
				log.Fatalf("REDIS_URL: %v", err)
			}
			rdb = redis.NewClient(opt)
			defer rdb.Close()
			log.Print("redis: npm registry cache enabled (REDIS_URL)")
		} else {
			log.Print("warning: REDIS_URL unset; npm scans will not use Redis cache")
		}

		scanHandlers := handlers.NewScans(pool, rdb)

		// Public route — no JWT required (auditors click this link)
		app.Get("/api/share/:token", scanHandlers.ViewShareLink)

		api := app.Group("/api", handlers.SupabaseJWTAuth(jwtSecret))
		api.Get("/dashboard/metrics", scanHandlers.GetDashboardMetrics)
		api.Get("/dashboard/stats", scanHandlers.GetDashboardStats)
		api.Post("/projects", scanHandlers.CreateProject)
		api.Get("/projects", scanHandlers.ListProjects)
		api.Get("/projects/:projectID/scans", scanHandlers.ListProjectScans)
		api.Post("/scans", scanHandlers.CreateScan)
		api.Get("/scans", scanHandlers.ListAllScans)
		api.Get("/scans/:scanID", scanHandlers.GetScan)
		api.Get("/scans/:scanID/compliance", scanHandlers.GetCompliance)
		api.Get("/scans/:scanID/report/pdf", scanHandlers.DownloadPDFReport)
		api.Get("/scans/:scanID/vulnerabilities", scanHandlers.GetScanVulnerabilities)
		api.Get("/vulnerabilities", scanHandlers.GetAllVulnerabilities)
		api.Post("/scans/:scanID/sbom", scanHandlers.GenerateSBOM)
		api.Get("/sboms/:sbomID/download", scanHandlers.DownloadSBOM)
		api.Post("/sboms/:sbomID/share", scanHandlers.CreateShareLink)
		api.Get("/sboms/:sbomID/shares", scanHandlers.ListShareLinks)
		log.Print("/api routes enabled (DATABASE_URL + SUPABASE_JWT_SECRET)")


	} else {
		log.Print("warning: /api routes disabled — set DATABASE_URL and SUPABASE_JWT_SECRET (e.g. in apps/api/.env) to enable scans")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("API listening on :%s", port)
	log.Fatal(app.Listen(":" + port))
}

func extractToken(c *fiber.Ctx) string {
	authHeader := c.Get(fiber.HeaderAuthorization)
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}

	return strings.TrimSpace(c.Get("X-GitHub-Token"))
}

func contextWithTimeout(c *fiber.Ctx) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(c.UserContext(), 15*time.Second)
}
