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
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	rows, err := pool.Query(context.Background(), "SELECT id, compliance_score, ntia_compliant, eu_cra_compliant FROM scans LIMIT 10")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Println("ID | Score | NTIA | EU")
	for rows.Next() {
		var id string
		var score *int
		var ntia *bool
		var eu *bool
		rows.Scan(&id, &score, &ntia, &eu)
		sStr := "NULL"
		if score != nil { sStr = fmt.Sprintf("%d", *score) }
		nStr := "NULL"
		if ntia != nil { nStr = fmt.Sprintf("%v", *ntia) }
		eStr := "NULL"
		if eu != nil { eStr = fmt.Sprintf("%v", *eu) }
		fmt.Printf("%s | %s | %s | %s\n", id, sStr, nStr, eStr)
	}
}
