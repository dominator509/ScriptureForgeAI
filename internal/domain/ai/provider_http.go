package ai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
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
)

// ProviderHTTPConfig is the shared timeout/retry policy for AI provider calls.
type ProviderHTTPConfig struct {
	Timeout    time.Duration
	MaxRetries int
}

// LoadProviderHTTPConfig reads bounded provider settings from the environment.
func LoadProviderHTTPConfig() ProviderHTTPConfig {
	config := ProviderHTTPConfig{
		Timeout:    DefaultProviderTimeout,
		MaxRetries: DefaultProviderRetries,
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

	return config
}

// NewProviderHTTPClient creates a client with an explicit finite timeout.
func NewProviderHTTPClient(config ProviderHTTPConfig) *http.Client {
	if config.Timeout <= 0 || config.Timeout > MaxProviderTimeout {
		config.Timeout = DefaultProviderTimeout
	}
	return &http.Client{Timeout: config.Timeout}
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
