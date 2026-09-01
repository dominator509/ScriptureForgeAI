package ai

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultProviderTimeout preserves the current provider request budget when unset.
	DefaultProviderTimeout = 3500 * time.Millisecond
	// MaxProviderTimeout prevents a deployment typo from creating unbounded request work.
	MaxProviderTimeout = 30 * time.Second
	// DefaultProviderRetries keeps one bounded retry for transient provider failures.
	DefaultProviderRetries = 1
	// MaxProviderRetries prevents an environment value from multiplying provider cost.
	MaxProviderRetries = 3
	// MaxProviderResponseBytes bounds memory used to process an external provider response.
	MaxProviderResponseBytes int64 = 1 << 20
	// DefaultMaxOutputTokens bounds model output when the provider supports token budgets.
	DefaultMaxOutputTokens = 2048
	MaxOutputTokens        = 8192
	DefaultProviderHost    = "api.openai.com"
)

// ProviderHTTPConfig is the shared timeout/retry policy for AI provider calls.
type ProviderHTTPConfig struct {
	Timeout         time.Duration
	MaxRetries      int
	MaxOutputTokens int
}

// LoadAllowedProviderHosts returns exact hostnames permitted to receive provider credentials.
func LoadAllowedProviderHosts() []string {
	raw := strings.TrimSpace(os.Getenv("AI_ALLOWED_PROVIDER_HOSTS"))
	if raw == "" {
		return []string{DefaultProviderHost}
	}
	hosts := make([]string, 0)
	for _, candidate := range strings.Split(raw, ",") {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(candidate), "."))
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return []string{DefaultProviderHost}
	}
	return hosts
}

// ValidateProviderEndpoint prevents provider bearer credentials from being sent to an arbitrary endpoint.
func ValidateProviderEndpoint(endpoint string, allowedHosts []string) error {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("provider endpoint must be an absolute URL")
	}
	if parsed.User != nil {
		return fmt.Errorf("provider endpoint must not contain credentials")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	allowed := false
	if len(allowedHosts) == 0 {
		allowedHosts = LoadAllowedProviderHosts()
	}
	for _, candidate := range allowedHosts {
		if strings.EqualFold(host, strings.TrimSuffix(strings.TrimSpace(candidate), ".")) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("provider endpoint host is not allowlisted")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackProviderHost(host) {
		return nil
	}
	return fmt.Errorf("provider endpoint must use HTTPS")
}

func isLoopbackProviderHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// LoadProviderHTTPConfig reads bounded provider settings from the environment.
func LoadProviderHTTPConfig() ProviderHTTPConfig {
	config := ProviderHTTPConfig{
		Timeout:         DefaultProviderTimeout,
		MaxRetries:      DefaultProviderRetries,
		MaxOutputTokens: DefaultMaxOutputTokens,
	}

	if configured := os.Getenv("AI_HTTP_TIMEOUT_MS"); configured != "" {
		if millis, err := strconv.Atoi(configured); err == nil && millis > 0 {
			config.Timeout = time.Duration(millis) * time.Millisecond
			if config.Timeout > MaxProviderTimeout {
				config.Timeout = MaxProviderTimeout
			}
		}
	}
	if configured := os.Getenv("AI_MAX_RETRIES"); configured != "" {
		if retries, err := strconv.Atoi(configured); err == nil && retries >= 0 {
			config.MaxRetries = retries
			if config.MaxRetries > MaxProviderRetries {
				config.MaxRetries = MaxProviderRetries
			}
		}
	}
	if configured := os.Getenv("AI_MAX_OUTPUT_TOKENS"); configured != "" {
		if tokens, err := strconv.Atoi(configured); err == nil && tokens > 0 {
			config.MaxOutputTokens = tokens
			if config.MaxOutputTokens > MaxOutputTokens {
				config.MaxOutputTokens = MaxOutputTokens
			}
		}
	}

	return config
}

// NewProviderHTTPClient creates a client with an explicit finite timeout.
func NewProviderHTTPClient(config ProviderHTTPConfig) *http.Client {
	if config.Timeout <= 0 || config.Timeout > MaxProviderTimeout {
		config.Timeout = DefaultProviderTimeout
	}
	return &http.Client{
		Timeout: config.Timeout,
		// Provider requests carry bearer credentials. Never follow a redirect to
		// an origin that was not validated by the provider endpoint guard.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// DoProviderRequest retries only transient provider failures and rebuilds each request.
// Rebuilding is required because net/http consumes request bodies on every attempt.
func DoProviderRequest(ctx context.Context, client *http.Client, maxRetries int, buildRequest func() (*http.Request, error)) (*http.Response, error) {
	if client == nil {
		client = NewProviderHTTPClient(ProviderHTTPConfig{})
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	if maxRetries > MaxProviderRetries {
		maxRetries = MaxProviderRetries
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := buildRequest()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err == nil && !isTransientProviderStatus(resp.StatusCode) {
			return resp, nil
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("transient provider status: %d", resp.StatusCode)
			if attempt == maxRetries {
				return resp, nil
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if attempt < maxRetries {
			if err := waitProviderRetry(ctx, attempt); err != nil {
				return nil, err
			}
		}
	}

	return nil, lastErr
}

// ReadProviderResponseBody reads a provider response without allowing unbounded allocation.
func ReadProviderResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("provider response body is missing")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxProviderResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > MaxProviderResponseBytes {
		return nil, fmt.Errorf("provider response exceeds %d bytes", MaxProviderResponseBytes)
	}
	return body, nil
}

func isTransientProviderStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func waitProviderRetry(ctx context.Context, attempt int) error {
	delay := time.Duration(attempt+1) * 100 * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
