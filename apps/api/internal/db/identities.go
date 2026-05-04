package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrGitHubTokenUnavailable means no GitHub-linked identity or empty provider token was found.
var ErrGitHubTokenUnavailable = errors.New("github oauth token unavailable")

// GitHubOAuthTokenFromIdentities returns the GitHub OAuth access token for the user from auth.identities.
// Expects auth.identities with provider = 'github' and provider_token (or token-like fields in identity_data).
func GitHubOAuthTokenFromIdentities(ctx context.Context, db Querier, userID string) (string, error) {
	// First, try to get the GitHub OAuth token from auth.identities (user linked GitHub OAuth).
	var token sql.NullString
	err := db.QueryRow(ctx, `
		SELECT COALESCE(
			NULLIF(trim(provider_token), ''),
			NULLIF(trim(identity_data->>'provider_token'), ''),
			NULLIF(trim(identity_data->>'access_token'), '')
		)::text AS tok
		FROM auth.identities
		WHERE user_id = $1::uuid AND provider = 'github'
		ORDER BY updated_at DESC NULLS LAST
		LIMIT 1
	`, userID).Scan(&token)

	// Helper: return env fallback or ErrGitHubTokenUnavailable.
	envFallback := func() (string, error) {
		if envToken := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); envToken != "" {
			return envToken, nil
		}
		return "", fmt.Errorf("%w", ErrGitHubTokenUnavailable)
	}

	if err != nil {
		// No GitHub identity linked — fall back to server PAT.
		return envFallback()
	}
	if !token.Valid || strings.TrimSpace(token.String) == "" {
		// Identity exists but token is empty — fall back to server PAT.
		return envFallback()
	}
	return token.String, nil
}
