package main

import (
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
	name, version, deps, devDeps, err := scanner.ParsePackageJSON(data)
	fmt.Printf("Parsed %s@%s\n", name, version)
	fmt.Printf("Deps: %d\n", len(deps))
	for k, v := range deps {
		fmt.Printf("  %s: %s\n", k, v)
	}
	fmt.Printf("DevDeps: %d\n", len(devDeps))
	for k, v := range devDeps {
		fmt.Printf("  %s: %s\n", k, v)
	}
}
