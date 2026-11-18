// Package config loads and validates the geoblock JSON configuration file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Default values applied to optional fields that are missing from the file.
const (
	DefaultListenAddress           = ":2115"
	DefaultRedisCacheTTL           = 7 * 24 * time.Hour
	DefaultLookupBaseURL           = "http://ip-api.com"
	DefaultLookupRequestsPerMinute = 40
)

// placeholderValue is what older versions wrote into a freshly created config.
const placeholderValue = "CHANGE_ME"

// ErrExampleWritten is returned by Load when no config file existed and an
// example one was written in its place. The caller should tell the user to
// edit it and exit.
var ErrExampleWritten = errors.New("example config written")

// Config is the on-disk configuration. Field names match the original
// version of the program so existing config files keep working.
type Config struct {
	// InterfaceName is the network interface to capture on, e.g. "eth0".
	InterfaceName string `json:"InterfaceName"`
	// RedisDataBaseAddress is the host:port of the Redis cache.
	RedisDataBaseAddress string `json:"RedisDataBaseAddress"`
	// RedisPassword is optional.
	RedisPassword string `json:"RedisPassword,omitempty"`
	// RedisCacheTTL controls how long a resolved country is cached in Redis.
	RedisCacheTTL Duration `json:"RedisCacheTTL"`
	// ListOfBlockedCountryCodes holds ISO 3166-1 alpha-2 codes, e.g. "CN".
	ListOfBlockedCountryCodes []string `json:"ListOfBlockedCountryCodes"`
	// ListenAddress is where the /metrics endpoint is served.
	ListenAddress string `json:"ListenAddress"`
	// LookupBaseURL is the ip-api compatible endpoint, without the /json path.
	LookupBaseURL string `json:"LookupBaseURL"`
	// LookupRequestsPerMinute caps calls to the lookup API.
	LookupRequestsPerMinute int `json:"LookupRequestsPerMinute"`
	// DryRun logs block decisions instead of adding iptables rules.
	DryRun bool `json:"DryRun"`
}

// Duration is a time.Duration that is encoded in JSON as a string such as
// "168h" or "30m".
type Duration time.Duration

// MarshalJSON implements json.Marshaler.
func (duration Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(duration).String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (duration *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("duration must be a string like \"168h\": %w", err)
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*duration = Duration(parsed)
	return nil
}

// DefaultPath returns the config location used by earlier versions:
// $XDG_CONFIG_HOME/goPrometheusPacketMonitoring/config.json.
func DefaultPath() (string, error) {
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDirectory, "goPrometheusPacketMonitoring", "config.json"), nil
}

// Example returns a config with sensible placeholder values.
func Example() Config {
	return Config{
		InterfaceName:             "eth0",
		RedisDataBaseAddress:      "127.0.0.1:6379",
		RedisCacheTTL:             Duration(DefaultRedisCacheTTL),
		ListOfBlockedCountryCodes: []string{},
		ListenAddress:             DefaultListenAddress,
		LookupBaseURL:             DefaultLookupBaseURL,
		LookupRequestsPerMinute:   DefaultLookupRequestsPerMinute,
		DryRun:                    true,
	}
}

// Load reads, defaults and validates the config at path. If the file does not
// exist, an example config is written there and ErrExampleWritten is returned.
func Load(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if writeErr := writeExample(path); writeErr != nil {
			return Config{}, fmt.Errorf("config %s does not exist and writing an example failed: %w", path, writeErr)
		}
		return Config{}, fmt.Errorf("%w to %s: edit it and start again", ErrExampleWritten, path)
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(content)
}

// Parse decodes config JSON, fills in defaults and validates the result.
func Parse(content []byte) (Config, error) {
	var parsed Config
	if err := json.Unmarshal(content, &parsed); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	parsed.applyDefaults()
	if err := parsed.Validate(); err != nil {
		return Config{}, err
	}
	return parsed, nil
}

func (config *Config) applyDefaults() {
	if config.ListenAddress == "" {
		config.ListenAddress = DefaultListenAddress
	}
	if config.RedisCacheTTL == 0 {
		config.RedisCacheTTL = Duration(DefaultRedisCacheTTL)
	}
	if config.LookupBaseURL == "" {
		config.LookupBaseURL = DefaultLookupBaseURL
	}
	if config.LookupRequestsPerMinute == 0 {
		config.LookupRequestsPerMinute = DefaultLookupRequestsPerMinute
	}
	for index, countryCode := range config.ListOfBlockedCountryCodes {
		config.ListOfBlockedCountryCodes[index] = strings.ToUpper(strings.TrimSpace(countryCode))
	}
}

// Validate reports every problem with the config at once.
func (config Config) Validate() error {
	var problems []error
	if isUnset(config.InterfaceName) {
		problems = append(problems, errors.New("InterfaceName is required"))
	}
	if isUnset(config.RedisDataBaseAddress) {
		problems = append(problems, errors.New("RedisDataBaseAddress is required (host:port)"))
	}
	if config.RedisCacheTTL < 0 {
		problems = append(problems, errors.New("RedisCacheTTL must be positive"))
	}
	if config.LookupRequestsPerMinute < 0 {
		problems = append(problems, errors.New("LookupRequestsPerMinute must be positive"))
	}
	if parsedURL, err := url.Parse(config.LookupBaseURL); err != nil || parsedURL.Host == "" ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		problems = append(problems, fmt.Errorf("LookupBaseURL %q must be an http(s) URL", config.LookupBaseURL))
	}
	for _, countryCode := range config.ListOfBlockedCountryCodes {
		if !isCountryCode(countryCode) {
			problems = append(problems, fmt.Errorf("blocked country code %q is not a two-letter ISO code", countryCode))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	messages := make([]string, len(problems))
	for index, problem := range problems {
		messages[index] = problem.Error()
	}
	return fmt.Errorf("invalid config:\n  - %s", strings.Join(messages, "\n  - "))
}

func isUnset(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" || trimmed == placeholderValue
}

func isCountryCode(value string) bool {
	if len(value) != 2 {
		return false
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func writeExample(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(Example(), "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(append(content, '\n'))
	return errors.Join(writeErr, file.Close())
}
