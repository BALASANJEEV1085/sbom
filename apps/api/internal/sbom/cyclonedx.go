package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbom-io/api/internal/scanner"
	"github.com/sbom-io/api/internal/vuln"
)

// ---------------------------------------------------------------------------
// CycloneDX 1.5 structs
// ---------------------------------------------------------------------------

type CycloneDXBOM struct {
	BOMFormat       string         `json:"bomFormat"`   // always "CycloneDX"
	SpecVersion     string         `json:"specVersion"` // always "1.5"
	SerialNumber    string         `json:"serialNumber"` // "urn:uuid:{uuid}"
	Version         int            `json:"version"`      // always 1
	Metadata        BOMMetadata    `json:"metadata"`
	Components      []BOMComponent `json:"components"`
	Dependencies    []Dependency   `json:"dependencies"`
	Vulnerabilities []BOMVuln      `json:"vulnerabilities,omitempty"`
}

type BOMMetadata struct {
	Timestamp string        `json:"timestamp"`           // RFC3339
	Tools     []BOMTool     `json:"tools"`
	Component *BOMComponent `json:"component,omitempty"` // root project
}

type BOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type BOMComponent struct {
	Type         string                 `json:"type"`    // "library"
	BOMREF       string                 `json:"bom-ref"` // "{name}@{version}"
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	PURL         string                 `json:"purl"` // pkg:{ecosystem}/{name}@{version}
	Licenses     []BOMComponentLicense  `json:"licenses,omitempty"`
	ExternalRefs []BOMExternalRef       `json:"externalReferences,omitempty"`
}

type BOMComponentLicense struct {
	License BOMLicense `json:"license"`
}

type BOMLicense struct {
	ID string `json:"id"` // SPDX license ID e.g. "MIT"
}

type BOMExternalRef struct {
	Type string `json:"type"` // "website"
	URL  string `json:"url"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type BOMVuln struct {
	ID          string         `json:"id"` // CVE ID
	Source      BOMVulnSource  `json:"source"`
	Ratings     []BOMVulnRating `json:"ratings,omitempty"`
	Description string         `json:"description,omitempty"`
}

type BOMVulnSource struct {
	Name string `json:"name"` // "NVD"
	URL  string `json:"url"`
}

type BOMVulnRating struct {
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity"` // "critical","high","medium","low"
	Method   string  `json:"method"`   // "CVSSv31"
}

// ---------------------------------------------------------------------------
// ScanInfo carries top-level scan metadata
// ---------------------------------------------------------------------------

type ScanInfo struct {
	ID        string
	RepoName  string
	RepoURL   string
	Ecosystem string
}

// ---------------------------------------------------------------------------
// GenerateCycloneDX builds a CycloneDX 1.5 JSON SBOM.
// Returns (jsonBytes, sha256hex, error).
// ---------------------------------------------------------------------------

func GenerateCycloneDX(
	scan ScanInfo,
	components []scanner.Package,
	vulns []vuln.ComponentVuln,
) ([]byte, string, error) {

	// 1. Metadata ------------------------------------------------------------
	rootPURL := buildPURL(scan.Ecosystem, scan.RepoName, "")
	rootComponent := &BOMComponent{
		Type:    "library",
		BOMREF:  "root",
		Name:    scan.RepoName,
		Version: "",
		PURL:    rootPURL,
	}

	metadata := BOMMetadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: []BOMTool{
			{Vendor: "SBOM.io", Name: "sbom-io-scanner", Version: "1.0.0"},
		},
		Component: rootComponent,
	}

	// 2. Components ----------------------------------------------------------
	bomComponents := make([]BOMComponent, 0, len(components))
	for _, pkg := range components {
		c := BOMComponent{
			Type:    "library",
			BOMREF:  bomRef(pkg.Name, pkg.Version),
			Name:    pkg.Name,
			Version: pkg.Version,
			PURL:    buildPURL(pkg.Ecosystem, pkg.Name, pkg.Version),
		}

		// Licenses
		if spdxID := mapToSPDX(pkg.License); spdxID != "" {
			c.Licenses = []BOMComponentLicense{
				{License: BOMLicense{ID: spdxID}},
			}
		}

		// External refs
		if pkg.Homepage != "" {
			c.ExternalRefs = []BOMExternalRef{
				{Type: "website", URL: pkg.Homepage},
			}
		}

		bomComponents = append(bomComponents, c)
	}

	// 3. Dependencies --------------------------------------------------------
	// Build a map: parentRef → []childRef
	depMap := make(map[string][]string) // parentRef → children refs

	// Seed root entry
	depMap["root"] = []string{}

	for _, pkg := range components {
		ref := bomRef(pkg.Name, pkg.Version)
		if pkg.Depth == 0 {
			depMap["root"] = append(depMap["root"], ref)
		} else if pkg.ParentName != "" {
			// We don't have the parent's resolved version here, so we match
			// by parent name against the components slice.
			parentRef := findParentRef(pkg.ParentName, components)
			if parentRef == "" {
				parentRef = pkg.ParentName // fallback
			}
			depMap[parentRef] = append(depMap[parentRef], ref)
		}
	}

	dependencies := make([]Dependency, 0, len(depMap))
	for ref, children := range depMap {
		if children == nil {
			children = []string{}
		}
		dependencies = append(dependencies, Dependency{
			Ref:       ref,
			DependsOn: children,
		})
	}

	// 4. Vulnerabilities -----------------------------------------------------
	var bomVulns []BOMVuln
	if len(vulns) > 0 {
		for _, v := range vulns {
			bv := BOMVuln{
				ID: v.CVEID,
				Source: BOMVulnSource{
					Name: "NVD",
					URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVEID),
				},
				Description: v.Summary,
			}
			if v.Severity != "" {
				bv.Ratings = []BOMVulnRating{
					{
						Severity: strings.ToLower(v.Severity),
						Method:   "CVSSv31",
					},
				}
			}
			bomVulns = append(bomVulns, bv)
		}
	}

	// 5. Assemble BOM --------------------------------------------------------
	bom := CycloneDXBOM{
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.5",
		SerialNumber:    "urn:uuid:" + uuid.New().String(),
		Version:         1,
		Metadata:        metadata,
		Components:      bomComponents,
		Dependencies:    dependencies,
		Vulnerabilities: bomVulns,
	}

	// 6. Marshal -------------------------------------------------------------
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("cyclonedx: marshal failed: %w", err)
	}

	// 7. SHA-256 -------------------------------------------------------------
	sum := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sum[:])

	return data, hashHex, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// bomRef returns the canonical bom-ref for a package.
func bomRef(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

// buildPURL constructs a Package URL per the PURL spec.
func buildPURL(ecosystem, name, version string) string {
	eco := strings.ToLower(ecosystem)
	var purlType string
	switch eco {
	case "npm":
		purlType = "npm"
	case "pip", "pypi":
		purlType = "pypi"
	case "maven":
		purlType = "maven"
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			if version != "" {
				return fmt.Sprintf("pkg:maven/%s/%s@%s", parts[0], parts[1], version)
			}
			return fmt.Sprintf("pkg:maven/%s/%s", parts[0], parts[1])
		}
	default:
		purlType = eco
	}

	if version != "" {
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	}
	return fmt.Sprintf("pkg:%s/%s", purlType, name)
}

// mapToSPDX maps common freeform license strings to SPDX identifiers.
// Returns "" if the license is unknown or empty — caller should skip.
func mapToSPDX(license string) string {
	if license == "" {
		return ""
	}
	norm := strings.ToLower(strings.TrimSpace(license))
	switch {
	case norm == "mit":
		return "MIT"
	case strings.Contains(norm, "apache") && strings.Contains(norm, "2"):
		return "Apache-2.0"
	case norm == "isc":
		return "ISC"
	case strings.HasPrefix(norm, "bsd"):
		return "BSD-3-Clause"
	case strings.Contains(norm, "gpl-3") || strings.Contains(norm, "gplv3"):
		return "GPL-3.0-only"
	case strings.Contains(norm, "gpl-2") || strings.Contains(norm, "gplv2"):
		return "GPL-2.0-only"
	case strings.Contains(norm, "lgpl-2.1"):
		return "LGPL-2.1-only"
	case strings.Contains(norm, "mpl") && strings.Contains(norm, "2"):
		return "MPL-2.0"
	case norm == "unlicensed" || norm == "unlicense":
		return "Unlicense"
	case norm == "0bsd":
		return "0BSD"
	case norm == "cc0-1.0":
		return "CC0-1.0"
	default:
		return "" // unknown — skip
	}
}

// findParentRef looks up the first component with the given name and returns
// its bom-ref. Falls back to empty string if not found.
func findParentRef(parentName string, components []scanner.Package) string {
	for _, pkg := range components {
		if pkg.Name == parentName {
			return bomRef(pkg.Name, pkg.Version)
		}
	}
	return ""
}
