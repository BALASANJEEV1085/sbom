package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load(".env")
	dbURL := os.Getenv("DATABASE_URL")
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	var id, status string
	err = pool.QueryRow(ctx, "SELECT id, status FROM scans ORDER BY created_at DESC LIMIT 1").Scan(&id, &status)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Latest Scan: %s, Status: %s\n", id, status)

	var count int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM components WHERE scan_id = $1", id).Scan(&count)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Components found: %d\n", count)
}
