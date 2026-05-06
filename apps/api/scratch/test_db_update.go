package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/sbom-io/api/internal/compliance"
)

func main() {
	godotenv.Load(".env")
	dbURL := os.Getenv("DATABASE_URL")
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	ctx := context.Background()
	// Try to update a dummy scan or just check if we can execute the update
	// We'll use a transaction that we roll back
	tx, err := pool.Begin(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback(ctx)

	detail := compliance.NTIAResult{Score: 100, Compliant: true}
	_, err = tx.Exec(ctx, `
		UPDATE scans 
		SET compliance_score = $2, 
		    ntia_compliant = $3, 
		    eu_cra_compliant = $4, 
		    compliance_detail = $5 
		WHERE id = '00000000-0000-0000-0000-000000000000'::uuid
	`, "00000000-0000-0000-0000-000000000000", 100, true, false, detail)

	if err != nil {
		fmt.Printf("Update failed: %v\n", err)
	} else {
		fmt.Println("Update syntax/schema check passed")
	}
}
