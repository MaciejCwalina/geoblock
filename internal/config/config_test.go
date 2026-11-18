package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErr     []string
		checkResult func(t *testing.T, parsed Config)
	}{
		{
			name: "legacy config gets defaults",
			content: `{"RedisDataBaseAddress":"127.0.0.1:6379","InterfaceName":"enp4s0",
				"ListOfBlockedCountryCodes":["cn"," ru "]}`,
			checkResult: func(t *testing.T, parsed Config) {
				if parsed.ListenAddress != DefaultListenAddress {
					t.Errorf("ListenAddress = %q", parsed.ListenAddress)
				}
				if time.Duration(parsed.RedisCacheTTL) != DefaultRedisCacheTTL {
					t.Errorf("RedisCacheTTL = %v", time.Duration(parsed.RedisCacheTTL))
				}
				if parsed.LookupBaseURL != DefaultLookupBaseURL {
					t.Errorf("LookupBaseURL = %q", parsed.LookupBaseURL)
				}
				if parsed.LookupRequestsPerMinute != DefaultLookupRequestsPerMinute {
					t.Errorf("LookupRequestsPerMinute = %d", parsed.LookupRequestsPerMinute)
				}
				if !slices.Equal(parsed.ListOfBlockedCountryCodes, []string{"CN", "RU"}) {
					t.Errorf("country codes = %v", parsed.ListOfBlockedCountryCodes)
				}
			},
		},
		{
			name: "all fields set",
			content: `{"RedisDataBaseAddress":"redis:6379","InterfaceName":"eth0","RedisCacheTTL":"24h",
				"ListenAddress":"127.0.0.1:9000","LookupBaseURL":"http://mock:8080","LookupRequestsPerMinute":10,"DryRun":true}`,
			checkResult: func(t *testing.T, parsed Config) {
				if time.Duration(parsed.RedisCacheTTL) != 24*time.Hour || parsed.ListenAddress != "127.0.0.1:9000" ||
					parsed.LookupBaseURL != "http://mock:8080" || parsed.LookupRequestsPerMinute != 10 || !parsed.DryRun {
					t.Errorf("unexpected config %+v", parsed)
				}
			},
		},
		{
			name:    "placeholders from old versions are rejected",
			content: `{"RedisDataBaseAddress":"CHANGE_ME","InterfaceName":"CHANGE_ME"}`,
			wantErr: []string{"InterfaceName is required", "RedisDataBaseAddress is required"},
		},
		{
			name:    "empty object",
			content: `{}`,
			wantErr: []string{"InterfaceName is required", "RedisDataBaseAddress is required"},
		},
		{
			name:    "bad country code",
			content: `{"RedisDataBaseAddress":"r:1","InterfaceName":"eth0","ListOfBlockedCountryCodes":["CHN","C1"]}`,
			wantErr: []string{`"CHN" is not a two-letter`, `"C1" is not a two-letter`},
		},
		{
			name:    "bad lookup url",
			content: `{"RedisDataBaseAddress":"r:1","InterfaceName":"eth0","LookupBaseURL":"ftp://x"}`,
			wantErr: []string{"LookupBaseURL"},
		},
		{
			name:    "negative values",
			content: `{"RedisDataBaseAddress":"r:1","InterfaceName":"eth0","RedisCacheTTL":"-1h","LookupRequestsPerMinute":-5}`,
			wantErr: []string{"RedisCacheTTL must be positive", "LookupRequestsPerMinute must be positive"},
		},
		{
			name:    "ttl must be a duration string",
			content: `{"RedisDataBaseAddress":"r:1","InterfaceName":"eth0","RedisCacheTTL":3600}`,
			wantErr: []string{"duration must be a string"},
		},
		{
			name:    "invalid json",
			content: `{"InterfaceName":`,
			wantErr: []string{"parse config"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse([]byte(test.content))
			if len(test.wantErr) > 0 {
				if err == nil {
					t.Fatalf("expected error containing %q", test.wantErr)
				}
				for _, fragment := range test.wantErr {
					if !strings.Contains(err.Error(), fragment) {
						t.Errorf("error %q does not contain %q", err, fragment)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			test.checkResult(t, parsed)
		})
	}
}

func TestLoadWritesExampleWhenMissing(t *testing.T) {
	tests := []struct {
		name             string
		relativePath     string
		createsDirectory bool
	}{
		// The old version crashed with a nil pointer in this case.
		{"directory exists, file missing", "config.json", false},
		{"directory missing", filepath.Join("nested", "config.json"), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), test.relativePath)

			_, err := Load(path)
			if !errors.Is(err, ErrExampleWritten) {
				t.Fatalf("err = %v, want ErrExampleWritten", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q should mention the path", err)
			}

			wantPermissions := map[string]os.FileMode{path: 0o600}
			if test.createsDirectory {
				wantPermissions[filepath.Dir(path)] = 0o700
			}
			for checkedPath, wantPermission := range wantPermissions {
				fileInfo, err := os.Stat(checkedPath)
				if err != nil {
					t.Fatal(err)
				}
				if permissions := fileInfo.Mode().Perm(); permissions != wantPermission {
					t.Errorf("%s permissions = %o, want %o", checkedPath, permissions, wantPermission)
				}
			}

			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var example Config
			if err := json.Unmarshal(content, &example); err != nil {
				t.Fatalf("example is not valid JSON: %v", err)
			}
			if !example.DryRun {
				t.Error("example config should default to dry run")
			}
			// Once written, the example loads cleanly.
			if _, err := Load(path); err != nil {
				t.Errorf("loading the example: %v", err)
			}
		})
	}
}

func TestLoadExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"RedisDataBaseAddress":"127.0.0.1:6379","InterfaceName":"eth0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.InterfaceName != "eth0" {
		t.Errorf("InterfaceName = %q", parsed.InterfaceName)
	}
}

func TestDurationRoundTrip(t *testing.T) {
	encoded, err := json.Marshal(Duration(90 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"1h30m0s"` {
		t.Errorf("encoded = %s", encoded)
	}
	var decoded Duration
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if time.Duration(decoded) != 90*time.Minute {
		t.Errorf("decoded = %v", time.Duration(decoded))
	}
}
