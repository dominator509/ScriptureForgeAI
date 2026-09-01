package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
)

// protectedMetricsHandler keeps the API Prometheus surface private outside
// explicit local development modes while allowing the existing handler to
// retain its method and output behavior.
func protectedMetricsHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresConfiguredMetricsAuthForEnvironment(os.Getenv("DEPLOYMENT_ENVIRONMENT")) {
			next.ServeHTTP(w, r)
			return
		}

		expected := strings.TrimSpace(os.Getenv("METRICS_AUTH_TOKEN"))
		if expected == "" {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		provided, ok := metricsBearerToken(r.Header.Get("Authorization"))
		if !ok || !metricsTokensEqual(expected, provided) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requiresConfiguredMetricsAuthForEnvironment(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "", "development", "dev", "test", "local":
		return false
	default:
		return true
	}
}

func metricsBearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func metricsTokensEqual(expected, provided string) bool {
	expectedDigest := sha256.Sum256([]byte(expected))
	providedDigest := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(expectedDigest[:], providedDigest[:]) == 1
}
