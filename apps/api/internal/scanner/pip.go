package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// PypiResponse represents the JSON response from PyPI
type PypiResponse struct {
	Info struct {
		Version     string            `json:"version"`
		License     string            `json:"license"`
		HomePage    string            `json:"home_page"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
}

func parsePipRequirement(req string) (string, string) {
	req = strings.Split(req, ";")[0] // Remove environment markers
	req = strings.TrimSpace(req)

	idx := strings.IndexAny(req, "=><~")
	if idx == -1 {
		pkgName := req
		if bIdx := strings.Index(pkgName, "["); bIdx != -1 {
			pkgName = pkgName[:bIdx]
		}
		return strings.TrimSpace(pkgName), ""
	}

	pkgName := req[:idx]
	if bIdx := strings.Index(pkgName, "["); bIdx != -1 {
		pkgName = pkgName[:bIdx]
	}

	version := req[idx:]
	version = strings.TrimLeft(version, "=><~ \t")

	return strings.TrimSpace(pkgName), strings.TrimSpace(version)
}

// ParseRequirementsTxt parses requirements.txt and returns map of package to version.
func ParseRequirementsTxt(data []byte) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		if commentIdx := strings.Index(line, " #"); commentIdx != -1 {
			line = strings.TrimSpace(line[:commentIdx])
		}

		pkgName, version := parsePipRequirement(line)
		if pkgName != "" {
			result[pkgName] = version
		}
	}
	return result
}

// ParsePyprojectToml parses pyproject.toml and returns map of package to version.
func ParsePyprojectToml(data []byte) map[string]string {
	result := make(map[string]string)
	content := string(data)

	projectIdx := strings.Index(content, "[project]")
	if projectIdx == -1 {
		return result
	}

	projectSection := content[projectIdx+len("[project]"):]

	nextSectionIdx := strings.Index(projectSection, "\n[")
	if nextSectionIdx != -1 {
		projectSection = projectSection[:nextSectionIdx]
	}

	depsIdx := strings.Index(projectSection, "dependencies")
	if depsIdx == -1 {
		return result
	}

	depsSection := projectSection[depsIdx:]
	startBracket := strings.Index(depsSection, "[")
	if startBracket == -1 {
		return result
	}
	endBracket := strings.Index(depsSection[startBracket:], "]")
	if endBracket == -1 {
		return result
	}

	arrContent := depsSection[startBracket : startBracket+endBracket]

	strMatches := regexp.MustCompile(`"([^"]+)"|'([^']+)'`).FindAllStringSubmatch(arrContent, -1)
	for _, m := range strMatches {
		val := m[1]
		if val == "" {
			val = m[2]
		}
		pkgName, version := parsePipRequirement(val)
		if pkgName != "" {
			result[pkgName] = version
		}
	}

	return result
}

// ResolveVersionPip resolves a pip package version and metadata from PyPI.
func ResolveVersionPip(ctx context.Context, rdb *redis.Client, pkgName, version string) (Package, error) {
	isExact := version != ""

	cacheKey := fmt.Sprintf("pip:%s:%s", pkgName, version)

	if rdb != nil {
		cached, err := rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			var pkg Package
			if json.Unmarshal([]byte(cached), &pkg) == nil {
				return pkg, nil
			}
		}
	}

	var urlStr string
	if isExact {
		urlStr = fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkgName, version)
	} else {
		urlStr = fmt.Sprintf("https://pypi.org/pypi/%s/json", pkgName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return Package{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Package{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		log.Printf("Warning: pip package not found: %s@%s", pkgName, version)
		return Package{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return Package{}, fmt.Errorf("pypi api returned %d for %s", resp.StatusCode, pkgName)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Package{}, err
	}

	var pypi PypiResponse
	if err := json.Unmarshal(body, &pypi); err != nil {
		return Package{}, err
	}

	homepage := pypi.Info.HomePage
	if homepage == "" && pypi.Info.ProjectURLs != nil {
		if hp, ok := pypi.Info.ProjectURLs["Homepage"]; ok {
			homepage = hp
		}
	}

	pkg := Package{
		Name:      pkgName,
		Version:   pypi.Info.Version,
		License:   pypi.Info.License,
		Homepage:  homepage,
		Ecosystem: "pip",
		Depth:     0,
	}

	if rdb != nil {
		if payload, err := json.Marshal(pkg); err == nil {
			rdb.Set(ctx, cacheKey, payload, 24*time.Hour)
		}
	}

	return pkg, nil
}

// ScanPip scans a pip dependency file and resolves all dependencies.
func ScanPip(ctx context.Context, rdb *redis.Client, fileBytes []byte, fileType string) ([]Package, error) {
	var deps map[string]string

	if fileType == "pyproject.toml" {
		deps = ParsePyprojectToml(fileBytes)
	} else if fileType == "requirements.txt" {
		deps = ParseRequirementsTxt(fileBytes)
	} else {
		return nil, fmt.Errorf("unsupported pip file type: %s", fileType)
	}

	var pkgs []Package
	var mu sync.Mutex

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for name, version := range deps {
		wg.Add(1)
		go func(pkgName, pkgVer string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pkg, err := ResolveVersionPip(ctx, rdb, pkgName, pkgVer)
			if err != nil {
				log.Printf("ResolveVersionPip error for %s: %v", pkgName, err)
				return
			}
			if pkg.Name != "" {
				mu.Lock()
				pkgs = append(pkgs, pkg)
				mu.Unlock()
			}
		}(name, version)
	}

	wg.Wait()
	return pkgs, nil
}
