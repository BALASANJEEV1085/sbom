package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env — try the api dir (.env right next to go.mod) then the repo root.
	loaded := false
	for _, p := range []string{".env", "../../.env"} {
		if err := godotenv.Load(p); err == nil {
			fmt.Println("Loaded env from:", p)
			loaded = true
			break
		}
	}
	if !loaded {
		fmt.Println("Warning: no .env file found, relying on OS environment")
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Find all *.sql files in migrations/ (relative to apps/api where go run is called)
	migrationsDir := "migrations"
	entries, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		log.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(entries)

	if len(entries) == 0 {
		log.Fatal("no migration files found in", migrationsDir)
	}

	for _, f := range entries {
		sql, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("read %s: %v", f, err)
		}
		fmt.Printf("→ applying %s ... ", filepath.Base(f))
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			log.Fatalf("\nFAILED %s: %v", f, err)
		}
		fmt.Println("OK")
	}

	fmt.Println("All migrations applied successfully.")
}
