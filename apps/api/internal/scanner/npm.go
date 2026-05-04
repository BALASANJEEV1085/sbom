package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	npmRegistryBase = "https://registry.npmjs.org"
	maxConcurrency  = 10
	npmRedisTTL     = 24 * time.Hour
)

type Package struct {
	Name        string
	Version     string
	VersionSpec string
	License     string
	Homepage    string
	Ecosystem   string
	Depth       int
	ParentName  string
}

var (
	resolveCache sync.Map // key: "<pkg>@<spec>", value: resolvedPackageMeta
)

type resolvedPackageMeta struct {
	Version      string            `json:"version"`
	License      string            `json:"license"`
	Homepage     string            `json:"homepage"`
	Dependencies map[string]string `json:"dependencies"`
}

type npmManifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	License         interface{}       `json:"license"`
	Homepage        string            `json:"homepage"`
}

func npmCacheKey(pkgName, versionSpec string) string {
	return "npm:" + pkgName + ":" + versionSpec
}

func cleanVersion(spec string) string {
	spec = strings.TrimSpace(spec)

	if spec == "*" || spec == "x" || spec == "X" || spec == "" {
		return ""
	}

	if strings.Contains(spec, " ") || strings.Contains(spec, "||") {
		parts := strings.Fields(strings.ReplaceAll(spec, "||", " "))
		for _, part := range parts {
			cleaned := cleanVersion(part)
			if cleaned != "" {
				return cleaned
			}
		}
		return ""
	}

	spec = strings.TrimPrefix(spec, "^")
	spec = strings.TrimPrefix(spec, "~")
	spec = strings.TrimPrefix(spec, ">=")
	spec = strings.TrimPrefix(spec, "<=")
	spec = strings.TrimPrefix(spec, ">")
	spec = strings.TrimPrefix(spec, "<")
	spec = strings.TrimPrefix(spec, "=")
	return strings.TrimSpace(spec)
}

func ParsePackageJSON(data []byte) (name, version string, deps map[string]string, devDeps map[string]string, err error) {
	var manifest npmManifest
	if err = json.Unmarshal(data, &manifest); err != nil {
		return "", "", nil, nil, fmt.Errorf("parse package.json: %w", err)
	}

	deps = make(map[string]string)
	for k, v := range manifest.Dependencies {
		deps[k] = cleanVersion(v)
	}

	devDeps = make(map[string]string)
	for k, v := range manifest.DevDependencies {
		devDeps[k] = cleanVersion(v)
	}

	return manifest.Name, manifest.Version, deps, devDeps, nil
}

// ResolveVersion resolves an npm dist-tag or semver range to an exact version and license.
// rdb may be nil to skip Redis caching.
func ResolveVersion(ctx context.Context, rdb *redis.Client, pkgName, versionSpec string) (exactVersion string, license string, err error) {
	meta, err := resolvePackageMeta(ctx, rdb, pkgName, versionSpec, nil)
	if err != nil {
		return "", "", err
	}
	return meta.Version, meta.License, nil
}

func ResolveDependencies(ctx context.Context, rdb *redis.Client, deps map[string]string, maxDepth int) ([]Package, error) {
	if maxDepth < 0 {
		return nil, errors.New("maxDepth must be >= 0")
	}

	sem := make(chan struct{}, maxConcurrency)
	seen := map[string]Package{}
	var seenMu sync.Mutex

	var walk func(context.Context, map[string]string, int, string, *sync.WaitGroup)

	walk = func(ctx context.Context, current map[string]string, depth int, parent string, wg *sync.WaitGroup) {
		defer wg.Done()

		if depth > maxDepth || len(current) == 0 {
			return
		}

		for name, spec := range current {
			if ctx.Err() != nil {
				return
			}

			wg.Add(1)
			go func(pkgName, versionSpec string, d int, parentName string) {
				defer wg.Done()

				sem <- struct{}{}
				meta, err := resolvePackageMeta(ctx, rdb, pkgName, versionSpec, nil)
				<-sem
				if err != nil {
					log.Printf("ResolveDependencies: skipping %s@%s: %v", pkgName, versionSpec, err)
					return
				}

				pkg := Package{
					Name:        pkgName,
					Version:     meta.Version,
					VersionSpec: versionSpec,
					License:     meta.License,
					Homepage:    meta.Homepage,
					Ecosystem:   "npm",
					Depth:       d,
					ParentName:  parentName,
				}

				key := pkg.Name + "@" + pkg.Version
				added := false

				seenMu.Lock()
				existing, exists := seen[key]
				if !exists || d < existing.Depth {
					seen[key] = pkg
					added = true
				}
				seenMu.Unlock()

				if !added {
					return
				}

				if d < maxDepth && len(meta.Dependencies) > 0 {
					childWG := &sync.WaitGroup{}
					childWG.Add(1)
					go walk(ctx, meta.Dependencies, d+1, pkgName, childWG)
					childWG.Wait()
				}
			}(name, spec, depth, parent)
		}
	}

	rootWG := &sync.WaitGroup{}
	rootWG.Add(1)
	go walk(ctx, deps, 0, "", rootWG)
	rootWG.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	pkgs := make([]Package, 0, len(seen))
	for _, pkg := range seen {
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// ScanNPM walks npm dependencies from a package.json body. rdb may be nil to skip Redis caching.
func ScanNPM(ctx context.Context, rdb *redis.Client, packageJSONBytes []byte) ([]Package, error) {
	_, _, deps, devDeps, err := ParsePackageJSON(packageJSONBytes)
	if err != nil {
		return nil, err
	}

	combined := make(map[string]string, len(deps)+len(devDeps))
	for name, spec := range deps {
		combined[name] = spec
	}
	for name, spec := range devDeps {
		if _, exists := combined[name]; !exists {
			combined[name] = spec
		}
	}

	return ResolveDependencies(ctx, rdb, combined, 3)
}

func fetchNPMRegistryJSON(ctx context.Context, endpoint string) ([]byte, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("create npm request: %w", err)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("npm request failed: %w", err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		code := resp.StatusCode
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, code, fmt.Errorf("read npm response: %w", readErr)
		}

		if code == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return nil, code, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}

		return body, code, nil
	}
	return nil, http.StatusTooManyRequests, fmt.Errorf("npm registry rate limited after retry")
}

func resolvePackageMeta(ctx context.Context, rdb *redis.Client, pkgName, versionSpec string, externalSem chan struct{}) (resolvedPackageMeta, error) {
	cacheKey := pkgName + "@" + versionSpec
	if cached, ok := resolveCache.Load(cacheKey); ok {
		return cached.(resolvedPackageMeta), nil
	}

	select {
	case <-ctx.Done():
		return resolvedPackageMeta{}, ctx.Err()
	default:
	}

	if externalSem != nil {
		// caller already handles semaphore for this request path
	}

	redisKey := npmCacheKey(pkgName, versionSpec)
	if rdb != nil {
		s, err := rdb.Get(ctx, redisKey).Result()
		if err == nil {
			var meta resolvedPackageMeta
			if uerr := json.Unmarshal([]byte(s), &meta); uerr == nil && meta.Version != "" {
				if meta.Dependencies == nil {
					meta.Dependencies = map[string]string{}
				}
				resolveCache.Store(cacheKey, meta)
				return meta, nil
			}
		} else if err != redis.Nil {
			// Redis unavailable or protocol error — continue to registry
		}
	}

	escapedName := url.PathEscape(pkgName)
	cleanSpec := cleanVersion(versionSpec)
	if cleanSpec == "" {
		cleanSpec = "latest"
	}
	escapedSpec := url.PathEscape(cleanSpec)
	endpoint := fmt.Sprintf("%s/%s/%s", npmRegistryBase, escapedName, escapedSpec)

	body, status, err := fetchNPMRegistryJSON(ctx, endpoint)
	if err != nil {
		return resolvedPackageMeta{}, err
	}

	if status < 200 || status >= 300 {
		return resolvedPackageMeta{}, fmt.Errorf("npm registry returned status %d for %s@%s", status, pkgName, versionSpec)
	}

	var manifest npmManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return resolvedPackageMeta{}, fmt.Errorf("decode npm response: %w", err)
	}

	if manifest.Dependencies == nil {
		manifest.Dependencies = map[string]string{}
	}

	meta := resolvedPackageMeta{
		Version:      manifest.Version,
		License:      stringifyLicense(manifest.License),
		Homepage:     strings.TrimSpace(manifest.Homepage),
		Dependencies: manifest.Dependencies,
	}

	if meta.Version == "" {
		return resolvedPackageMeta{}, fmt.Errorf("npm response missing version for %s@%s", pkgName, versionSpec)
	}

	resolveCache.Store(cacheKey, meta)

	if rdb != nil {
		if payload, err := json.Marshal(meta); err == nil {
			_ = rdb.Set(ctx, redisKey, payload, npmRedisTTL).Err()
		}
	}

	return meta, nil
}

func stringifyLicense(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case map[string]interface{}:
		if typ, ok := t["type"].(string); ok {
			return strings.TrimSpace(typ)
		}
	}
	return ""
}
