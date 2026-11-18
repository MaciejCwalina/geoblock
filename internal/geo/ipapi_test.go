package geo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func newTestClient(serverURL string, limiter *rate.Limiter) *IPAPIClient {
	if limiter == nil {
		limiter = rate.NewLimiter(rate.Inf, 1)
	}
	return NewIPAPIClientWithLimiter(serverURL, &http.Client{Timeout: time.Second}, limiter)
}

func TestIPAPIClientLocate(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		body         string
		want         Location
		wantErr      string
		wantSentinel error
	}{
		{
			name:   "success",
			status: http.StatusOK,
			body:   `{"status":"success","country":"China","countryCode":"CN"}`,
			want:   Location{CountryCode: "CN", Country: "China"},
		},
		{
			name:    "api reports failure",
			status:  http.StatusOK,
			body:    `{"status":"fail","message":"reserved range"}`,
			wantErr: `status "fail": reserved range`,
		},
		{
			name:    "success without country code",
			status:  http.StatusOK,
			body:    `{"status":"success"}`,
			wantErr: "no country code",
		},
		{
			name:         "rate limited",
			status:       http.StatusTooManyRequests,
			body:         ``,
			wantSentinel: ErrRateLimited,
		},
		{
			name:    "server error",
			status:  http.StatusInternalServerError,
			body:    `oops`,
			wantErr: "unexpected HTTP status 500",
		},
		{
			name:    "bad json",
			status:  http.StatusOK,
			body:    `{"status":`,
			wantErr: "decode response",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requestedPath string
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestedPath = request.URL.Path
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()

			location, err := newTestClient(server.URL+"/", nil).Locate(context.Background(), netip.MustParseAddr("1.1.1.1"))
			if requestedPath != "/json/1.1.1.1" {
				t.Errorf("requested path %q", requestedPath)
			}
			switch {
			case test.wantSentinel != nil:
				if !errors.Is(err, test.wantSentinel) {
					t.Fatalf("err = %v, want %v", err, test.wantSentinel)
				}
			case test.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, test.wantErr)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if location != test.want {
					t.Errorf("location = %+v, want %+v", location, test.want)
				}
			}
		})
	}
}

func TestIPAPIClientTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	client := NewIPAPIClientWithLimiter(server.URL, &http.Client{Timeout: 50 * time.Millisecond}, rate.NewLimiter(rate.Inf, 1))
	if _, err := client.Locate(context.Background(), netip.MustParseAddr("1.1.1.1")); err == nil {
		t.Fatal("expected a timeout error")
	}
}

func TestIPAPIClientRateLimit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = writer.Write([]byte(`{"status":"success","country":"United States","countryCode":"US"}`))
	}))
	defer server.Close()

	// One token, refilled once an hour: the first call goes through, the
	// second must wait and gives up when its context expires.
	client := newTestClient(server.URL, rate.NewLimiter(rate.Every(time.Hour), 1))
	address := netip.MustParseAddr("8.8.8.8")

	if _, err := client.Locate(context.Background(), address); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.Locate(ctx, address); err == nil {
		t.Fatal("second call should be held back by the rate limiter")
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("server saw %d requests, want 1", got)
	}
}

func TestNewIPAPIClientRate(t *testing.T) {
	client := NewIPAPIClient("http://example.invalid", 45)
	if got, want := float64(client.limiter.Limit()), 45.0/60.0; got < want*0.99 || got > want*1.01 {
		t.Errorf("limit = %v per second, want %v", got, want)
	}
	if client.httpClient.Timeout == 0 {
		t.Error("HTTP client must have a timeout")
	}
}
