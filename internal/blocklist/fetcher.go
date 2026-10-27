package blocklist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxBlocklistSize = 10 * 1024 * 1024 // 10MB

// FetchURL fetches blocklist content from url and returns parsed domains.
func FetchURL(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxBlocklistSize)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return ParseHostsOrDomains(string(content)), nil
}
