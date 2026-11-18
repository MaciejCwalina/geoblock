package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// ErrRateLimited is returned when the API answers 429 Too Many Requests.
var ErrRateLimited = errors.New("lookup API rate limit exceeded")

// ipAPIFields limits the response to what is needed (smaller and faster).
const ipAPIFields = "status,message,country,countryCode"

type ipAPIResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
}

// IPAPIClient queries an ip-api.com compatible endpoint. All requests pass
// through a token-bucket limiter so the free tier quota is never exceeded.
type IPAPIClient struct {
	baseURL    string
	httpClient *http.Client
	limiter    *rate.Limiter
}

// NewIPAPIClient returns a client for baseURL (e.g. "http://ip-api.com")
// allowing at most requestsPerMinute requests.
func NewIPAPIClient(baseURL string, requestsPerMinute int) *IPAPIClient {
	return NewIPAPIClientWithLimiter(
		baseURL,
		&http.Client{Timeout: 5 * time.Second},
		rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), 1),
	)
}

// NewIPAPIClientWithLimiter is NewIPAPIClient with explicit dependencies.
func NewIPAPIClientWithLimiter(baseURL string, httpClient *http.Client, limiter *rate.Limiter) *IPAPIClient {
	return &IPAPIClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		limiter:    limiter,
	}
}

// Locate implements Locator. It waits for the rate limiter, so it can block
// for a long time; callers must not call it from latency-sensitive paths.
func (client *IPAPIClient) Locate(ctx context.Context, address netip.Addr) (Location, error) {
	if err := client.limiter.Wait(ctx); err != nil {
		return Location{}, fmt.Errorf("waiting for rate limiter: %w", err)
	}

	requestURL := client.baseURL + "/json/" + address.String() + "?fields=" + ipAPIFields
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return Location{}, err
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Location{}, fmt.Errorf("lookup %s: %w", address, err)
	}
	defer func() { _ = response.Body.Close() }()

	switch {
	case response.StatusCode == http.StatusTooManyRequests:
		return Location{}, fmt.Errorf("lookup %s: %w", address, ErrRateLimited)
	case response.StatusCode != http.StatusOK:
		return Location{}, fmt.Errorf("lookup %s: unexpected HTTP status %s", address, response.Status)
	}

	var decoded ipAPIResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&decoded); err != nil {
		return Location{}, fmt.Errorf("lookup %s: decode response: %w", address, err)
	}
	if decoded.Status != "success" {
		return Location{}, fmt.Errorf("lookup %s: API returned status %q: %s", address, decoded.Status, decoded.Message)
	}
	if decoded.CountryCode == "" {
		return Location{}, fmt.Errorf("lookup %s: API response has no country code", address)
	}
	return Location{CountryCode: decoded.CountryCode, Country: decoded.Country}, nil
}
