package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sbom-io/api/internal/db"
)

type ComponentVuln struct {
	ComponentID  string
	CVEID        string
	Severity     string // CRITICAL/HIGH/MEDIUM/LOW
	Summary      string
	FixedVersion string
}

type OSVQuery struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Affected []struct {
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
	Severity         []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

// QueryOSV fetches vulnerabilities from osv.dev
func QueryOSV(ctx context.Context, pkgName, version, ecosystem string) ([]ComponentVuln, error) {
	osvEco := ecosystem
	switch strings.ToLower(ecosystem) {
	case "npm":
		osvEco = "npm"
	case "pip", "pypi":
		osvEco = "PyPI"
	case "maven":
		osvEco = "Maven"
	case "go":
		osvEco = "Go"
	}

	query := OSVQuery{
		Package: OSVPackage{
			Name:      pkgName,
			Ecosystem: osvEco,
		},
		Version: version,
	}

	bodyBytes, _ := json.Marshal(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api returned %d", resp.StatusCode)
	}

	var osvResp OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	var vulns []ComponentVuln
	for _, v := range osvResp.Vulns {
		cveID := v.ID
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				cveID = alias
				break
			}
		}

		severity := "LOW"
		var parsedScore float64
		for _, sev := range v.Severity {
			if !strings.HasPrefix(sev.Score, "CVSS:") {
				fmt.Sscanf(sev.Score, "%f", &parsedScore)
			}
		}

		if dbSev, ok := v.DatabaseSpecific["severity"].(string); ok && parsedScore == 0 {
			s := strings.ToUpper(dbSev)
			if s == "MODERATE" {
				s = "MEDIUM"
			}
			if s == "CRITICAL" || s == "HIGH" || s == "MEDIUM" || s == "LOW" {
				severity = s
			}
		}

		if parsedScore >= 9.0 {
			severity = "CRITICAL"
		} else if parsedScore >= 7.0 {
			severity = "HIGH"
		} else if parsedScore >= 4.0 {
			severity = "MEDIUM"
		} else if parsedScore > 0 {
			severity = "LOW"
		}

		var fixedVersion string
		for _, aff := range v.Affected {
			for _, r := range aff.Ranges {
				for _, evt := range r.Events {
					if fx, ok := evt["fixed"]; ok {
						fixedVersion = fx
					}
				}
			}
		}

		vulns = append(vulns, ComponentVuln{
			CVEID:        cveID,
			Severity:     severity,
			Summary:      v.Summary,
			FixedVersion: fixedVersion,
		})
	}
	return vulns, nil
}

// MatchVulnerabilities fetches all components for a scan and queries OSV for each
func MatchVulnerabilities(ctx context.Context, pool *pgxpool.Pool, scanID string) ([]ComponentVuln, error) {
	_, components, err := db.GetScanWithComponents(ctx, pool, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get components: %w", err)
	}

	if len(components) == 0 {
		return nil, nil
	}

	var allVulns []ComponentVuln
	var mu sync.Mutex
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	for _, comp := range components {
		wg.Add(1)
		go func(c db.Component) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vulns, err := QueryOSV(ctx, c.Name, c.Version, c.Ecosystem)
			if err != nil {
				log.Printf("QueryOSV error for %s@%s: %v", c.Name, c.Version, err)
				return
			}

			mu.Lock()
			for _, v := range vulns {
				v.ComponentID = c.ID
				allVulns = append(allVulns, v)
			}
			mu.Unlock()
		}(comp)
	}

	wg.Wait()
	return allVulns, nil
}

// SaveComponentVulns saves the identified vulnerabilities to the database
func SaveComponentVulns(ctx context.Context, pool *pgxpool.Pool, vulns []ComponentVuln) error {
	if len(vulns) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	query := `
		INSERT INTO component_vulnerabilities (component_id, cve_id, severity, summary, fixed_version)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (component_id, cve_id) DO UPDATE SET
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary,
			fixed_version = EXCLUDED.fixed_version,
			created_at = NOW()
	`

	for _, v := range vulns {
		batch.Queue(query, v.ComponentID, v.CVEID, v.Severity, v.Summary, v.FixedVersion)
	}

	br := pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < len(vulns); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("batch exec error at index %d: %w", i, err)
		}
	}

	return nil
}

// GetScanVulnSummary returns count of vulnerabilities by severity for a scan
func GetScanVulnSummary(ctx context.Context, pool *pgxpool.Pool, scanID string) (critical, high, medium, low int, err error) {
	query := `
		SELECT severity, COUNT(*) 
		FROM component_vulnerabilities
		JOIN components ON components.id = component_vulnerabilities.component_id
		WHERE components.scan_id = $1 
		GROUP BY severity
	`
	rows, err := pool.Query(ctx, query, scanID)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			continue
		}
		switch strings.ToUpper(sev) {
		case "CRITICAL":
			critical += count
		case "HIGH":
			high += count
		case "MEDIUM":
			medium += count
		case "LOW":
			low += count
		}
	}

	return critical, high, medium, low, rows.Err()
}
