package scanner

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type MavenDep struct {
	GroupID    string
	ArtifactID string
	Version    string
	Scope      string
}

type pomProject struct {
	XMLName    xml.Name          `xml:"project"`
	GroupID    string            `xml:"groupId"`
	ArtifactID string            `xml:"artifactId"`
	Version    string            `xml:"version"`
	Properties pomProperties     `xml:"properties"`
	// dependencies can be in <dependencies> or <dependencyManagement><dependencies>
	Dependencies []pomDependency `xml:"dependencies>dependency"`
	
	// For metadata parsing
	Name        string        `xml:"name"`
	Description string        `xml:"description"`
	URL         string        `xml:"url"`
	Licenses    []pomLicense  `xml:"licenses>license"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomProperties struct {
	Entries map[string]string
}

func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch elem := t.(type) {
		case xml.StartElement:
			var content string
			if err := d.DecodeElement(&content, &elem); err != nil {
				return err
			}
			p.Entries[elem.Name.Local] = content
		case xml.EndElement:
			if elem.Name == start.Name {
				return nil
			}
		}
	}
	return nil
}

type pomLicense struct {
	Name string `xml:"name"`
}

func ParsePOMXML(data []byte) (groupID, artifactID, version string, deps []MavenDep, err error) {
	var proj pomProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return "", "", "", nil, err
	}

	groupID = proj.GroupID
	artifactID = proj.ArtifactID
	version = proj.Version

	resolveProp := func(v string) string {
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			propName := v[2 : len(v)-1]
			if val, ok := proj.Properties.Entries[propName]; ok {
				return val
			}
		}
		return v
	}

	for _, d := range proj.Dependencies {
		scope := strings.TrimSpace(d.Scope)
		if scope == "test" {
			continue // skip test dependencies
		}
		
		dep := MavenDep{
			GroupID:    resolveProp(strings.TrimSpace(d.GroupID)),
			ArtifactID: resolveProp(strings.TrimSpace(d.ArtifactID)),
			Version:    resolveProp(strings.TrimSpace(d.Version)),
			Scope:      scope,
		}
		deps = append(deps, dep)
	}

	return groupID, artifactID, version, deps, nil
}

func fetchLatestMavenVersion(ctx context.Context, groupID, artifactID string) (string, error) {
	url := fmt.Sprintf("https://search.maven.org/solrsearch/select?q=g:%s+AND+a:%s&rows=1&wt=json", groupID, artifactID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Response struct {
			Docs []struct {
				LatestVersion string `json:"latestVersion"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Response.Docs) > 0 {
		return result.Response.Docs[0].LatestVersion, nil
	}
	return "", fmt.Errorf("no version found for %s:%s", groupID, artifactID)
}

func fetchMavenMetadata(ctx context.Context, groupID, artifactID, version string) (pomProject, error) {
	groupPath := strings.ReplaceAll(groupID, ".", "/")
	url := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom", groupPath, artifactID, version, artifactID, version)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return pomProject{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return pomProject{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return pomProject{}, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return pomProject{}, err
	}

	var proj pomProject
	if err := xml.Unmarshal(body, &proj); err != nil {
		return pomProject{}, err
	}
	return proj, nil
}

func ResolveVersionMaven(ctx context.Context, rdb *redis.Client, groupID, artifactID, version string) (Package, error) {
	if version == "" {
		v, err := fetchLatestMavenVersion(ctx, groupID, artifactID)
		if err != nil {
			return Package{}, err
		}
		version = v
	}

	cacheKey := fmt.Sprintf("maven:%s:%s:%s", groupID, artifactID, version)
	if rdb != nil {
		cached, err := rdb.Get(ctx, cacheKey).Result()
		if err == nil {
			var p Package
			if err := json.Unmarshal([]byte(cached), &p); err == nil {
				return p, nil
			}
		}
	}

	proj, err := fetchMavenMetadata(ctx, groupID, artifactID, version)
	
	var license string
	var homepage string
	if err == nil {
		if len(proj.Licenses) > 0 {
			license = proj.Licenses[0].Name
		}
		homepage = proj.URL
	}

	pkg := Package{
		Name:      groupID + ":" + artifactID,
		Version:   version,
		License:   license,
		Homepage:  homepage,
		Ecosystem: "maven",
	}

	if rdb != nil {
		if bytes, err := json.Marshal(pkg); err == nil {
			rdb.Set(ctx, cacheKey, bytes, 24*time.Hour)
		}
	}

	return pkg, nil
}

func ScanMaven(ctx context.Context, rdb *redis.Client, pomXMLBytes []byte) ([]Package, error) {
	_, _, _, deps, err := ParsePOMXML(pomXMLBytes)
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, dep := range deps {
		if ctx.Err() != nil {
			break
		}
		
		wg.Add(1)
		sem <- struct{}{}
		go func(d MavenDep) {
			defer wg.Done()
			defer func() { <-sem }()
			
			pkg, err := ResolveVersionMaven(ctx, rdb, d.GroupID, d.ArtifactID, d.Version)
			if err != nil {
				if pkg.Name == "" {
					pkg = Package{
						Name:      d.GroupID + ":" + d.ArtifactID,
						Version:   d.Version,
						Ecosystem: "maven",
					}
				}
			}
			
			pkg.Depth = 0
			
			mu.Lock()
			pkgs = append(pkgs, pkg)
			mu.Unlock()
			
		}(dep)
	}

	wg.Wait()
	return pkgs, nil
}
