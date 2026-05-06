package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sbom-io/api/internal/scanner"
)

var nonAlphanumRE = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// sanitizeSPDXID replaces non-alphanumeric chars with "-" and prefixes "SPDXRef-".
func sanitizeSPDXID(s string) string {
	safe := nonAlphanumRE.ReplaceAllString(s, "-")
	safe = strings.Trim(safe, "-")
	return "SPDXRef-" + safe
}

// licenseOrNoAssertion returns the SPDX ID if mappable, otherwise "NOASSERTION".
func licenseOrNoAssertion(license string) string {
	if id := mapToSPDX(license); id != "" {
		return id
	}
	return "NOASSERTION"
}

// GenerateSPDX builds an SPDX 2.3 tag-value (.spdx) document.
// Returns (textBytes, sha256hex, error).
func GenerateSPDX(scan ScanInfo, components []scanner.Package) ([]byte, string, error) {
	var sb strings.Builder

	// -------------------------------------------------------------------------
	// Document header
	// -------------------------------------------------------------------------
	sb.WriteString("SPDXVersion: SPDX-2.3\n")
	sb.WriteString("DataLicense: CC0-1.0\n")
	sb.WriteString("SPDXID: SPDXRef-DOCUMENT\n")
	sb.WriteString(fmt.Sprintf("DocumentName: %s\n", scan.RepoName))
	sb.WriteString(fmt.Sprintf("DocumentNamespace: https://sbom.io/spdx/%s\n", scan.ID))
	sb.WriteString("Creator: Tool: SBOM.io-1.0.0\n")
	sb.WriteString(fmt.Sprintf("Created: %s\n", time.Now().UTC().Format(time.RFC3339)))

	// -------------------------------------------------------------------------
	// Packages
	// -------------------------------------------------------------------------
	for _, pkg := range components {
		sb.WriteString("\n") // blank line between header / packages

		sb.WriteString(fmt.Sprintf("PackageName: %s\n", pkg.Name))
		sb.WriteString(fmt.Sprintf("SPDXID: %s\n", sanitizeSPDXID(pkg.Name+"-"+pkg.Version)))
		sb.WriteString(fmt.Sprintf("PackageVersion: %s\n", pkg.Version))
		sb.WriteString("PackageDownloadLocation: NOASSERTION\n")
		sb.WriteString("FilesAnalyzed: false\n")

		lic := licenseOrNoAssertion(pkg.License)
		sb.WriteString(fmt.Sprintf("PackageLicenseConcluded: %s\n", lic))
		sb.WriteString(fmt.Sprintf("PackageLicenseDeclared: %s\n", lic))
		sb.WriteString("PackageCopyrightText: NOASSERTION\n")

		purl := buildPURL(pkg.Ecosystem, pkg.Name, pkg.Version)
		sb.WriteString(fmt.Sprintf("ExternalRef: PACKAGE-MANAGER purl %s\n", purl))
	}

	data := []byte(sb.String())

	sum := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sum[:])

	return data, hashHex, nil
}
