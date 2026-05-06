//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5"
)

func main() {
	dbURL := "postgresql://postgres.pifoeymzjwwungcbxyyl:Bala%40swathi1001@aws-1-ap-southeast-1.pooler.supabase.com:5432/postgres"
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, "SELECT column_name FROM information_schema.columns WHERE table_name = 'sboms'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Println("Columns in 'sboms':")
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatal(err)
		}
		fmt.Println("-", name)
	}
}
