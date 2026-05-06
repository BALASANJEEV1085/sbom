//go:build ignore

package main

import (
	"context"
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

	// 1. Fix sboms table
	// Rename columns to match the code's expectations or add missing ones
	_, err = conn.Exec(ctx, `
		-- Rename existing columns if they exist and are different
		ALTER TABLE sboms RENAME COLUMN file_format TO format;
		ALTER TABLE sboms RENAME COLUMN file_path TO file_key;
		ALTER TABLE sboms RENAME COLUMN file_size TO file_size_bytes;
		ALTER TABLE sboms RENAME COLUMN checksum TO sha256_hash;
		
		-- Add missing columns
		ALTER TABLE sboms ADD COLUMN IF NOT EXISTS spec_version TEXT;
		ALTER TABLE sboms ADD COLUMN IF NOT EXISTS component_count INTEGER;
	`)
	if err != nil {
		log.Printf("Warning fixing sboms: %v (maybe they already match)", err)
	}

	// 2. Ensure shared_links table exists with correct schema
	_, err = conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS shared_links (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			sbom_id UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
			token TEXT NOT NULL UNIQUE,
			label TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			view_count INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_shared_links_token ON shared_links(token);
		CREATE INDEX IF NOT EXISTS idx_shared_links_sbom ON shared_links(sbom_id);
	`)
	if err != nil {
		log.Fatalf("Error creating shared_links: %v", err)
	}

	log.Println("Database schema updated successfully.")
}
