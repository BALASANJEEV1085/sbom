package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/sbom-io/api/internal/db"
	gh "github.com/sbom-io/api/internal/github"
	"github.com/sbom-io/api/internal/scanner"
)

const localsSupabaseUserID = "supabase_user_id"

// SupabaseJWTAuth validates the Authorization: Bearer JWT using Supabase's JWT secret (HS256).
// On success it stores the auth user id (JWT "sub") in fiber locals under localsSupabaseUserID.
func SupabaseJWTAuth(jwtSecret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
		if !strings.HasPrefix(strings.ToLower(raw), "bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing Authorization: Bearer token"})
		}
		tokenStr := strings.TrimSpace(raw[7:])
		if tokenStr == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "empty bearer token"})
		}

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
			alg, _ := t.Header["alg"].(string)

			// 1. Handle Modern ECC (ES256) - Now default for new Supabase projects
			if alg == "ES256" {
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("unexpected signing method %q for ES256", alg)
				}
				// Fetch public key from JWKS (or use cached/env public key)
				return getSupabasePublicKey(c.Context(), t.Header["kid"])
			}

			// 2. Handle Legacy Shared Secret (HS256)
			if alg == "HS256" {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method %q for HS256", alg)
				}
				if strings.TrimSpace(jwtSecret) == "" {
					return nil, fmt.Errorf("server misconfiguration: SUPABASE_JWT_SECRET is missing for HS256 validation")
				}
				return []byte(jwtSecret), nil
			}

			return nil, fmt.Errorf("unsupported signing method %q", alg)
		}, jwt.WithValidMethods([]string{"HS256", "ES256"}))

		if err != nil || !token.Valid {
			msg := "invalid or expired token"
			if err != nil {
				msg = err.Error()
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": msg})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token claims"})
		}

		sub, _ := claims["sub"].(string)
		if sub == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token missing sub claim"})
		}

		c.Locals(localsSupabaseUserID, sub)
		return c.Next()
	}
}

var (
	publicKeyCache = make(map[any]*ecdsa.PublicKey)
)

func getSupabasePublicKey(ctx context.Context, kid any) (*ecdsa.PublicKey, error) {
	if pk, ok := publicKeyCache[kid]; ok {
		return pk, nil
	}

	projectURL := strings.TrimRight(os.Getenv("SUPABASE_URL"), "/")
	if projectURL == "" {
		return nil, fmt.Errorf("SUPABASE_URL is not set")
	}

	jwksURL := projectURL + "/auth/v1/.well-known/jwks.json"
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	for _, k := range jwks.Keys {
		if k.Kid == kid || kid == nil {
			xBytes, _ := base64.RawURLEncoding.DecodeString(k.X)
			yBytes, _ := base64.RawURLEncoding.DecodeString(k.Y)
			pk := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
			publicKeyCache[k.Kid] = pk
			return pk, nil
		}
	}

	return nil, fmt.Errorf("public key not found for kid: %v", kid)
}

// SupabaseUserID returns the JWT subject set by SupabaseJWTAuth, or empty if unset.
func SupabaseUserID(c *fiber.Ctx) string {
	v, _ := c.Locals(localsSupabaseUserID).(string)
	return v
}

// Scans exposes /api scan endpoints. Use with SupabaseJWTAuth on the parent route group.
type Scans struct {
	DB    *pgxpool.Pool
	Redis *redis.Client // optional; used for npm registry cache when non-nil
}

func NewScans(pool *pgxpool.Pool, rdb *redis.Client) *Scans {
	return &Scans{DB: pool, Redis: rdb}
}

type createScanBody struct {
	GithubURL string `json:"github_url"`
	ProjectID string `json:"project_id"`
}

// CreateScan handles POST /api/scans.
func (h *Scans) CreateScan(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	var body createScanBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON body"})
	}
	body.GithubURL = strings.TrimSpace(body.GithubURL)
	body.ProjectID = strings.TrimSpace(body.ProjectID)
	if body.GithubURL == "" || body.ProjectID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "github_url and project_id are required",
		})
	}
	if _, err := uuid.Parse(body.ProjectID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid project_id"})
	}

	owner, repo, err := gh.ParseRepoURL(body.GithubURL)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid github_url: " + err.Error()})
	}

	ctx := c.UserContext()
	ok, err := db.ProjectOwnedByUser(ctx, h.DB, body.ProjectID, userID)
	if err != nil {
		log.Printf("CreateScan: project ownership check failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	if !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "project not found or access denied"})
	}

	githubToken, err := db.GitHubOAuthTokenFromIdentities(ctx, h.DB, userID)
	if err != nil {
		if errors.Is(err, db.ErrGitHubTokenUnavailable) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "github account not linked or token unavailable",
			})
		}
		log.Printf("CreateScan: load github credentials failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not load github credentials"})
	}

	scanID, err := db.CreateScan(ctx, h.DB, body.ProjectID)
	if err != nil {
		log.Printf("CreateScan: create scan record failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create scan"})
	}

	pool := h.DB
	go runScanJob(context.Background(), pool, h.Redis, scanID, githubToken, owner, repo)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"scan_id": scanID,
		"status":  "running",
	})
}

func runScanJob(ctx context.Context, pool *pgxpool.Pool, rdb *redis.Client, scanID, githubToken, owner, repo string) {
	scanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fail := func() {
		if err := db.UpdateScanStatus(scanCtx, pool, scanID, "failed"); err != nil {
			log.Printf("scan %s: mark failed: %v", scanID, err)
		}
	}

	pkgJSON, err := gh.FetchFile(scanCtx, githubToken, owner, repo, "package.json")
	if err != nil {
		log.Printf("scan %s: fetch package.json: %v", scanID, err)
		fail()
		return
	}

	pkgs, err := scanner.ScanNPM(scanCtx, rdb, pkgJSON)
	if err != nil {
		log.Printf("scan %s: scan npm: %v", scanID, err)
		fail()
		return
	}

	if err := db.SaveComponents(scanCtx, pool, scanID, pkgs); err != nil {
		log.Printf("scan %s: save components: %v", scanID, err)
		fail()
		return
	}

	if err := db.UpdateScanStatus(scanCtx, pool, scanID, "done"); err != nil {
		log.Printf("scan %s: mark done: %v", scanID, err)
	}
}

// GetScan handles GET /api/scans/:scanID.
func (h *Scans) GetScan(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	scanID := strings.TrimSpace(c.Params("scanID"))
	if _, err := uuid.Parse(scanID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid scan_id"})
	}

	ctx := c.UserContext()
	scan, components, err := db.GetScanWithComponents(ctx, h.DB, scanID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scan not found"})
		}
		log.Printf("GetScan: GetScanWithComponents failed for scanID %s: %v", scanID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	ok, err := db.ProjectOwnedByUser(ctx, h.DB, scan.ProjectID, userID)
	if err != nil {
		log.Printf("GetScan: project ownership check failed: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	if !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "access denied"})
	}

	pName, pURL, _ := db.GetProjectForUser(ctx, h.DB, scan.ProjectID, userID)
	repoTitle := "Repository"
	if owner, repo, err := gh.ParseRepoURL(pURL); err == nil {
		repoTitle = owner + "/" + repo
	}

	return c.JSON(fiber.Map{
		"scan": fiber.Map{
			"id":         scan.ID,
			"project_id": scan.ProjectID,
			"status":     scan.Status,
			"created_at": scan.CreatedAt,
		},
		"components": componentsJSON(components),
		"total":      len(components),
		"project": fiber.Map{
			"name":          pName,
			"github_url":    pURL,
			"display_title": repoTitle,
		},
	})
}

// ListProjectScans handles GET /api/projects/:projectID/scans.
func (h *Scans) ListProjectScans(c *fiber.Ctx) error {
	userID := SupabaseUserID(c)
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthenticated"})
	}

	projectID := strings.TrimSpace(c.Params("projectID"))
	if _, err := uuid.Parse(projectID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid project_id"})
	}

	ctx := c.UserContext()
	ok, err := db.ProjectOwnedByUser(ctx, h.DB, projectID, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	if !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "project not found or access denied"})
	}

	scans, err := db.ListScansForProject(ctx, h.DB, projectID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	out := make([]fiber.Map, 0, len(scans))
	for _, s := range scans {
		out = append(out, fiber.Map{
			"id":         s.ID,
			"project_id": s.ProjectID,
			"status":     s.Status,
			"created_at": s.CreatedAt,
		})
	}

	return c.JSON(fiber.Map{
		"scans": out,
		"total": len(out),
	})
}

func componentsJSON(components []db.Component) []fiber.Map {
	out := make([]fiber.Map, 0, len(components))
	for _, comp := range components {
		out = append(out, fiber.Map{
			"id":           comp.ID,
			"scan_id":      comp.ScanID,
			"name":         comp.Name,
			"version":      comp.Version,
			"version_spec": comp.VersionSpec,
			"license":      comp.License,
			"ecosystem":    comp.Ecosystem,
			"depth":        comp.Depth,
			"parent_name":  comp.ParentName,
			"created_at":   comp.CreatedAt,
		})
	}
	return out
}
