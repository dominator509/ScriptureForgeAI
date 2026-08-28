package main

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	defaultLocalBrowserOrigins = "http://localhost:3000,http://127.0.0.1:3000"
	allowedCORSMethods         = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
	allowedCORSHeaders         = "Accept, Authorization, Content-Type, X-CSRF-Token, X-ScriptureForge-Client"
	exposedCORSHeaders         = "Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Trace-ID"
)

func loadAllowedBrowserOrigins() (map[string]struct{}, *PlatformException) {
	raw := strings.TrimSpace(os.Getenv("ALLOWED_WS_ORIGINS"))
	if raw == "" {
		if requiresConfiguredBrowserOrigins() {
			return nil, configurationFault("ALLOWED_WS_ORIGINS environment variable is required in staging/production")
		}
		raw = defaultLocalBrowserOrigins
	}

	origins := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		normalized, err := normalizeBrowserOrigin(candidate)
		if err != nil || !validBrowserOriginForEnvironment(normalized) {
			return nil, configurationFault("ALLOWED_WS_ORIGINS contains an invalid browser origin")
		}
		origins[normalized] = struct{}{}
	}
	if len(origins) == 0 {
		return nil, configurationFault("ALLOWED_WS_ORIGINS must contain at least one browser origin")
	}
	return origins, nil
}

func requiresConfiguredBrowserOrigins() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOYMENT_ENVIRONMENT"))) {
	case "", "development", "dev", "test", "local":
		return false
	default:
		return true
	}
}

func normalizeBrowserOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", &url.Error{Op: "parse", URL: raw, Err: errInvalidBrowserOrigin{}}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Hostname() == "" {
		return "", &url.Error{Op: "parse", URL: raw, Err: errInvalidBrowserOrigin{}}
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

type errInvalidBrowserOrigin struct{}

func (errInvalidBrowserOrigin) Error() string { return "invalid browser origin" }

func validBrowserOriginForEnvironment(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if requiresConfiguredBrowserOrigins() {
		return parsed.Scheme == "https" && !isReservedBrowserOriginHost(host) && !isLocalOrPrivateBrowserOriginHost(host)
	}
	if parsed.Scheme == "http" {
		return isLocalBrowserOriginHost(host)
	}
	return parsed.Scheme == "https" && !isReservedBrowserOriginHost(host) && !isLocalOrPrivateBrowserOriginHost(host)
}

func isLocalBrowserOriginHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}

func isLocalOrPrivateBrowserOriginHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func isReservedBrowserOriginHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	return normalized == "example" ||
		strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		normalized == "test" ||
		strings.HasSuffix(normalized, ".test") ||
		normalized == "invalid" ||
		strings.HasSuffix(normalized, ".invalid")
}

func apiSecurityMiddleware(next http.Handler) http.Handler {
	origins, err := loadAllowedBrowserOrigins()
	if err != nil {
		origins = map[string]struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setAPISecurityHeaders(w, r)

		origin := strings.TrimSpace(r.Header.Get("Origin"))
		originAllowed := false
		if origin != "" {
			normalized, normalizeErr := normalizeBrowserOrigin(origin)
			_, originAllowed = origins[normalized]
			if normalizeErr != nil || !originAllowed {
				rejectBrowserOrigin(w)
				return
			}
			setCORSHeaders(w, origin)
		}

		if r.Method == http.MethodOptions {
			if !originAllowed || !validCORSPreflight(r) {
				rejectBrowserOrigin(w)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if browserCSRFRequired(r) && !csrfTokenMatchesRequest(r) {
			rejectCSRF(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setAPISecurityHeaders(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		header.Set("Cache-Control", "no-store")
	}
	if requiresConfiguredBrowserOrigins() {
		header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

func setCORSHeaders(w http.ResponseWriter, origin string) {
	header := w.Header()
	header.Add("Vary", "Origin")
	header.Add("Vary", "Access-Control-Request-Method")
	header.Add("Vary", "Access-Control-Request-Headers")
	header.Set("Access-Control-Allow-Origin", origin)
	header.Set("Access-Control-Allow-Credentials", "true")
	header.Set("Access-Control-Allow-Methods", allowedCORSMethods)
	header.Set("Access-Control-Allow-Headers", allowedCORSHeaders)
	header.Set("Access-Control-Expose-Headers", exposedCORSHeaders)
	header.Set("Access-Control-Max-Age", "600")
}

func validCORSPreflight(r *http.Request) bool {
	requestedMethod := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
	if requestedMethod != "" && requestedMethod != http.MethodGet && requestedMethod != http.MethodHead && requestedMethod != http.MethodPost && requestedMethod != http.MethodPut && requestedMethod != http.MethodPatch && requestedMethod != http.MethodDelete {
		return false
	}
	allowedHeaders := map[string]struct{}{
		"accept":                  {},
		"authorization":           {},
		"content-type":            {},
		"x-csrf-token":            {},
		"x-scriptureforge-client": {},
	}
	for _, requestedHeader := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		requestedHeader = strings.ToLower(strings.TrimSpace(requestedHeader))
		if requestedHeader == "" {
			continue
		}
		if _, ok := allowedHeaders[requestedHeader]; !ok {
			return false
		}
	}
	return true
}

func browserCSRFRequired(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/") || !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-ScriptureForge-Client")), "web") {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func rejectBrowserOrigin(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"origin_not_allowed"}`))
}

func rejectCSRF(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"csrf_token_invalid"}`))
}
