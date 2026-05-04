package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	apiBaseURL        = "https://api.github.com"
	apiVersionHeader  = "2022-11-28"
	defaultUserAgent  = "sbom-io-api"
	maxResponseLength = 2 << 20
)

type FileEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type RateLimitError struct {
	Message   string
	ResetTime string
}

func (e *RateLimitError) Error() string {
	if e == nil {
		return "github API rate limit exceeded"
	}
	if e.ResetTime != "" {
		return fmt.Sprintf("github API rate limit exceeded: %s (reset: %s)", e.Message, e.ResetTime)
	}
	if e.Message != "" {
		return fmt.Sprintf("github API rate limit exceeded: %s", e.Message)
	}
	return "github API rate limit exceeded"
}

type Client struct {
	token      string
	httpClient *http.Client
}

func NewClient(token string) *Client {
	return &Client{
		token:      token,
		httpClient: http.DefaultClient,
	}
}

func (c *Client) FetchFile(ctx context.Context, owner, repo, filepath string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("github client is nil")
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s", apiBaseURL, owner, repo, path.Clean(filepath))
	body, _, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Type     string `json:"type"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode github file response: %w", err)
	}

	if resp.Type != "file" {
		return nil, fmt.Errorf("path is not a file: %s", filepath)
	}
	if !strings.EqualFold(resp.Encoding, "base64") {
		return nil, fmt.Errorf("unsupported content encoding: %s", resp.Encoding)
	}

	cleanContent := strings.ReplaceAll(resp.Content, "\n", "")
	decoded, err := base64.StdEncoding.DecodeString(cleanContent)
	if err != nil {
		return nil, fmt.Errorf("decode base64 file content: %w", err)
	}

	return decoded, nil
}

func (c *Client) ListFiles(ctx context.Context, owner, repo, dirPath string) ([]FileEntry, error) {
	if c == nil {
		return nil, errors.New("github client is nil")
	}

	cleanPath := strings.TrimPrefix(path.Clean(dirPath), "/")
	if cleanPath == "." {
		cleanPath = ""
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s", apiBaseURL, owner, repo, cleanPath)
	body, _, err := c.doRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var entries []FileEntry
	if err := json.Unmarshal(body, &entries); err == nil {
		return entries, nil
	}

	var single FileEntry
	if err := json.Unmarshal(body, &single); err == nil && single.Path != "" {
		return []FileEntry{single}, nil
	}

	return nil, errors.New("unexpected github contents response format")
}

func ParseRepoURL(rawURL string) (owner, repo string, err error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", fmt.Errorf("parse repo URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", errors.New("invalid scheme: expected http or https")
	}
	if !strings.EqualFold(u.Host, "github.com") {
		return "", "", errors.New("invalid host: expected github.com")
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", errors.New("invalid repository URL path")
	}

	owner = strings.TrimSpace(parts[0])
	repo = strings.TrimSpace(parts[1])
	repo = strings.TrimSuffix(repo, ".git")

	if owner == "" || repo == "" {
		return "", "", errors.New("missing owner or repository name")
	}

	return owner, repo, nil
}

func (c *Client) doRequest(ctx context.Context, endpoint string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersionHeader)
	req.Header.Set("User-Agent", defaultUserAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("github request failed: %w", err)
	}
	defer resp.Body.Close()

	limitedReader := io.LimitReader(resp.Body, maxResponseLength)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, nil, fmt.Errorf("read github response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		var payload struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &payload)
		return nil, resp.Header, &RateLimitError{
			Message:   payload.Message,
			ResetTime: resp.Header.Get("X-RateLimit-Reset"),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header, fmt.Errorf("github API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, resp.Header, nil
}

// FetchFile downloads a single repository file using a GitHub OAuth or PAT access token.
func FetchFile(ctx context.Context, accessToken, owner, repo, filePath string) ([]byte, error) {
	return NewClient(accessToken).FetchFile(ctx, owner, repo, filePath)
}
