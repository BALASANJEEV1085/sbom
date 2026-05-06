package compliance

import (
	"fmt"
	"time"

	"github.com/sbom-io/api/internal/scanner"
)

type NTIAResult struct {
	Compliant        bool              `json:"compliant"`
	Score            int               `json:"score"` // 0-100
	Elements         []NTIAElement     `json:"elements"`
	FailedComponents []FailedComponent `json:"failed_components,omitempty"`
	Recommendations  []string          `json:"recommendations"`
}

type NTIAElement struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Coverage    int    `json:"coverage"` // percentage 0-100
	Detail      string `json:"detail"`
}

type FailedComponent struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Missing []string `json:"missing"` // which fields are missing
}

type SBOMMeta struct {
	AuthorName  string
	AuthorTool  string
	GeneratedAt time.Time
	RepoName    string
}

func CheckNTIA(components []scanner.Package, sbomMeta SBOMMeta) NTIAResult {
	result := NTIAResult{
		Elements: make([]NTIAElement, 7),
	}

	numComponents := len(components)

	// Element 1 — Supplier name
	supplierPassedCount := 0
	for _, c := range components {
		if c.Name != "" {
			supplierPassedCount++
		}
	}
	supplierCoverage := 100
	if numComponents > 0 {
		supplierCoverage = (supplierPassedCount * 100) / numComponents
	}
	result.Elements[0] = NTIAElement{
		Name:        "Supplier Name",
		Description: "Identify the supplier of each component.",
		Passed:      supplierCoverage == 100,
		Coverage:    supplierCoverage,
		Detail:      fmt.Sprintf("%d/%d components have supplier name", supplierPassedCount, numComponents),
	}

	// Element 2 — Component name
	namePassedCount := 0
	for _, c := range components {
		if c.Name != "" {
			namePassedCount++
		}
	}
	nameCoverage := 100
	if numComponents > 0 {
		nameCoverage = (namePassedCount * 100) / numComponents
	}
	result.Elements[1] = NTIAElement{
		Name:        "Component Name",
		Description: "Name of every component.",
		Passed:      nameCoverage == 100,
		Coverage:    nameCoverage,
		Detail:      fmt.Sprintf("%d/%d components have a name", namePassedCount, numComponents),
	}

	// Element 3 — Version
	versionPassedCount := 0
	var failedComponents []FailedComponent
	for _, c := range components {
		if c.Version != "" && c.Version != "unknown" {
			versionPassedCount++
		} else {
			failedComponents = append(failedComponents, FailedComponent{
				Name:    c.Name,
				Version: c.Version,
				Missing: []string{"version"},
			})
		}
	}
	versionCoverage := 100
	if numComponents > 0 {
		versionCoverage = (versionPassedCount * 100) / numComponents
	}
	result.Elements[2] = NTIAElement{
		Name:        "Version",
		Description: "Version string of every component.",
		Passed:      versionCoverage == 100,
		Coverage:    versionCoverage,
		Detail:      fmt.Sprintf("%d/%d components have valid version", versionPassedCount, numComponents),
	}
	if len(failedComponents) > 0 {
		result.FailedComponents = failedComponents
	} else {
		result.FailedComponents = make([]FailedComponent, 0)
	}

	// Element 4 — Unique identifiers (PURL)
	purlPassedCount := 0
	for _, c := range components {
		if c.Name != "" && c.Version != "" && c.Ecosystem != "" {
			purlPassedCount++
		}
	}
	purlCoverage := 100
	if numComponents > 0 {
		purlCoverage = (purlPassedCount * 100) / numComponents
	}
	result.Elements[3] = NTIAElement{
		Name:        "Other Unique Identifiers",
		Description: "PURL or CPE for each component.",
		Passed:      purlCoverage == 100,
		Coverage:    purlCoverage,
		Detail:      fmt.Sprintf("%d/%d components can form valid PURL", purlPassedCount, numComponents),
	}

	// Element 5 — Dependency relationships
	hasDependencies := false
	for _, c := range components {
		if c.Depth > 0 && c.ParentName != "" {
			hasDependencies = true
			break
		}
	}
	if !hasDependencies && numComponents > 1 {
		// "OR if all depth==0, still passes if component count > 1"
		hasDependencies = true
	}
	
	depPassed := hasDependencies
	if numComponents <= 1 && !hasDependencies {
		depPassed = false
	}
	if numComponents == 0 {
	    depPassed = false
	}

	result.Elements[4] = NTIAElement{
		Name:        "Dependency Relationships",
		Description: "How components relate to each other.",
		Passed:      depPassed,
		Coverage:    0,
		Detail:      fmt.Sprintf("Dependency relationships present: %v", depPassed),
	}
	if result.Elements[4].Passed {
		result.Elements[4].Coverage = 100
	}

	// Element 6 — SBOM author
	authorPassed := sbomMeta.AuthorName != "" && sbomMeta.AuthorTool != ""
	authorCoverage := 0
	if authorPassed {
		authorCoverage = 100
	}
	result.Elements[5] = NTIAElement{
		Name:        "Author of SBOM Data",
		Description: "Who generated the SBOM.",
		Passed:      authorPassed,
		Coverage:    authorCoverage,
		Detail:      fmt.Sprintf("Author Name: '%s', Author Tool: '%s'", sbomMeta.AuthorName, sbomMeta.AuthorTool),
	}

	// Element 7 — Timestamp
	now := time.Now()
	timestampPassed := !sbomMeta.GeneratedAt.IsZero() && now.Sub(sbomMeta.GeneratedAt) <= 365*24*time.Hour
	timestampCoverage := 0
	if timestampPassed {
		timestampCoverage = 100
	}
	result.Elements[6] = NTIAElement{
		Name:        "Timestamp",
		Description: "When the SBOM was created.",
		Passed:      timestampPassed,
		Coverage:    timestampCoverage,
		Detail:      fmt.Sprintf("Generated At: %s", sbomMeta.GeneratedAt.Format(time.RFC3339)),
	}

	// Score calculation
	passedCount := 0
	result.Recommendations = []string{}
	for i, e := range result.Elements {
		if e.Passed {
			passedCount++
		} else {
			// Recommendations
			switch i {
			case 0:
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Element 1 failed: %d components missing supplier name. Add supplier info to dependencies.", numComponents-supplierPassedCount))
			case 1:
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Element 2 failed: %d components missing component name. Ensure all dependencies have valid names.", numComponents-namePassedCount))
			case 2:
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Element 3 failed: %d components are missing version strings. Consider pinning all dependencies to exact versions.", numComponents-versionPassedCount))
			case 3:
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Element 4 failed: %d components cannot form valid PURLs. Ensure Name, Version, and Ecosystem exist.", numComponents-purlPassedCount))
			case 4:
				result.Recommendations = append(result.Recommendations, "Element 5 failed: No dependency relationships found. Ensure dependency graph is resolved.")
			case 5:
				result.Recommendations = append(result.Recommendations, "Element 6 failed: SBOM author info missing. Provide AuthorName and AuthorTool in metadata.")
			case 6:
				result.Recommendations = append(result.Recommendations, "Element 7 failed: Invalid or outdated timestamp. Ensure SBOM is generated with current timestamp.")
			}
		}
	}

	result.Score = (passedCount * 100) / 7
	result.Compliant = result.Score == 100

	return result
}

func CheckEUCRA(result NTIAResult) bool {
	return result.Compliant && result.Score >= 80
}
