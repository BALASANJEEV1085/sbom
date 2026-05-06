package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/sbom-io/api/internal/compliance"
	"github.com/sbom-io/api/internal/scanner"
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
	rows, err := pool.Query(ctx, "SELECT id FROM scans WHERE status = 'done'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var scanIDs []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		scanIDs = append(scanIDs, id)
	}
	rows.Close()

	fmt.Printf("Recalculating compliance for %d scans...\n", len(scanIDs))

	for _, id := range scanIDs {
		// Get components
		cRows, err := pool.Query(ctx, "SELECT name, version, ecosystem, depth, parent_name FROM components WHERE scan_id = $1", id)
		if err != nil {
			log.Printf("Scan %s: failed to get components: %v", id, err)
			continue
		}
		var pkgs []scanner.Package
		for cRows.Next() {
			var p scanner.Package
			cRows.Scan(&p.Name, &p.Version, &p.Ecosystem, &p.Depth, &p.ParentName)
			pkgs = append(pkgs, p)
		}
		cRows.Close()

		meta := compliance.SBOMMeta{
			AuthorName:  "SBOM.io",
			AuthorTool:  "sbom-io-scanner v1.0.0",
			GeneratedAt: time.Now(),
			RepoName:    "recalculated",
		}
		res := compliance.CheckNTIA(pkgs, meta)
		eu := compliance.CheckEUCRA(res)

		detailJSON, _ := json.Marshal(res)
		_, err = pool.Exec(ctx, `
			UPDATE scans 
			SET compliance_score = $2, 
			    ntia_compliant = $3, 
			    eu_cra_compliant = $4, 
			    compliance_detail = $5 
			WHERE id = $1::uuid
		`, id, res.Score, res.Compliant, eu, string(detailJSON))

		if err != nil {
			log.Printf("Scan %s: update failed: %v", id, err)
		} else {
			fmt.Printf("Scan %s: updated (Score: %d)\n", id, res.Score)
		}
	}
	fmt.Println("Done!")
}
