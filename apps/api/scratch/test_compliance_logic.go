package main

import (
	"fmt"
	"time"

	"github.com/sbom-io/api/internal/compliance"
	"github.com/sbom-io/api/internal/scanner"
)

func main() {
	pkgs := []scanner.Package{
		{Name: "test-pkg", Version: "1.0.0", Ecosystem: "npm"},
	}
	meta := compliance.SBOMMeta{
		AuthorName:  "Tester",
		AuthorTool:  "TestTool",
		GeneratedAt: time.Now(),
		RepoName:    "test-repo",
	}

	result := compliance.CheckNTIA(pkgs, meta)
	fmt.Printf("Score: %d\n", result.Score)
	fmt.Printf("Compliant: %v\n", result.Compliant)
	for i, el := range result.Elements {
		fmt.Printf("Element %d (%s): Passed=%v, Coverage=%d\n", i, el.Name, el.Passed, el.Coverage)
	}
}
