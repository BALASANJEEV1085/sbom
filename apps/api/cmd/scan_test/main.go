package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/sbom-io/api/internal/scanner"
)

func main() {
	resp, err := http.Get("https://raw.githubusercontent.com/BALASANJEEV1085/Portfolio/main/package.json")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	pkgs, err := scanner.ScanNPM(context.Background(), nil, data)
	if err != nil {
		fmt.Println("Scan error:", err)
		return
	}
	
	fmt.Printf("Total components found: %d\n", len(pkgs))
	
	// Just print the first 10 for sanity check
	for i, p := range pkgs {
		if i >= 10 {
			break
		}
		fmt.Printf("- %s@%s (depth %d, parent %s)\n", p.Name, p.Version, p.Depth, p.ParentName)
	}
}
