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

	tables := []string{"projects", "scans", "components", "vulnerabilities"}
	for _, t := range tables {
		fmt.Printf("\nTable: %s\n", t)
		rows, err := pool.Query(ctx, fmt.Sprintf(`
			SELECT column_name, data_type, is_nullable
			FROM information_schema.columns
			WHERE table_name = '%s'
		`, t))
		if err != nil {
			log.Fatal(err)
		}
		for rows.Next() {
			var name, dtype, nullable string
			rows.Scan(&name, &dtype, &nullable)
			fmt.Printf("  - %s: %s (nullable: %s)\n", name, dtype, nullable)
		}
		rows.Close()
	}
}
