package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scriptureforge/internal/domain/abuse"
	"scriptureforge/internal/domain/auth"
)

func exerciseRoute(t *testing.T, handler http.Handler, path string, body string) (int, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.RemoteAddr = "203.0.113.25:49152"
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, response
}

func exerciseRouteRaw(t *testing.T, handler http.Handler, path string, body string, remoteAddr string) (int, http.Header, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), response
}

func TestLegacyAuthRoutesUseCanonicalValidation(t *testing.T) {
	router := setupRoutes(nil, nil, nil)

	tests := []struct {
		name          string
		canonicalPath string
		legacyPath    string
		body          string
	}{
		{
			name:          "register",
			canonicalPath: "/api/v1/auth/register",
			legacyPath:    "/api/auth/register",
			body:          `{"email":"not-an-email","password":"short","organization_id":""}`,
		},
		{
			name:          "login",
			canonicalPath: "/api/v1/auth/login",
			legacyPath:    "/api/auth/login",
			body:          `{"email":"member@example.test","password":"password-without-org"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalStatus, canonicalError := exerciseRoute(t, router, tt.canonicalPath, tt.body)
			legacyStatus, legacyError := exerciseRoute(t, router, tt.legacyPath, tt.body)

			if legacyStatus != canonicalStatus {
				t.Fatalf("legacy status = %d, canonical status = %d", legacyStatus, canonicalStatus)
			}
			if legacyError.Category != canonicalError.Category || legacyError.Message != canonicalError.Message || legacyError.Code != canonicalError.Code {
				t.Fatalf("legacy error = %#v, canonical error = %#v", legacyError, canonicalError)
			}
		})
	}
}

func TestHealthRoutesExposeLivenessAndDependencyReadiness(t *testing.T) {
	router := setupRoutes(nil, nil, nil)

	liveRecorder := httptest.NewRecorder()
	router.ServeHTTP(liveRecorder, httptest.NewRequest(http.MethodGet, "/live", nil))
	if liveRecorder.Code != http.StatusOK {
		t.Fatalf("/live status = %d body = %q", liveRecorder.Code, liveRecorder.Body.String())
	}
	if !strings.Contains(liveRecorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("/live body = %q", liveRecorder.Body.String())
	}

	readyRecorder := httptest.NewRecorder()
	router.ServeHTTP(readyRecorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("/ready status = %d body = %q, want 503 without dependencies", readyRecorder.Code, readyRecorder.Body.String())
	}
	if !strings.Contains(readyRecorder.Body.String(), "dependencies_not_configured") {
		t.Fatalf("/ready body = %q", readyRecorder.Body.String())
	}
}

func TestLoadConfigDefaultsGRPCAddressOnlyForLocalDevelopment(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://local.example/scriptureforge")
	t.Setenv("REDIS_URL", "redis://local.example:6379")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
	for _, name := range []string{
		"HTTP_READ_HEADER_TIMEOUT_MS",
		"HTTP_READ_TIMEOUT_MS",
		"HTTP_WRITE_TIMEOUT_MS",
		"HTTP_IDLE_TIMEOUT_MS",
		"HTTP_MAX_HEADER_BYTES",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("GRPC_ENGINE_ADDRESS", "")
	t.Setenv("GRPC_ENGINE_SHARED_SECRET", "")
	t.Setenv("GRPC_ENGINE_TLS_CA_PEM", "")
	t.Setenv("GRPC_ENGINE_TLS_CLIENT_CERT_PEM", "")
	t.Setenv("GRPC_ENGINE_TLS_CLIENT_KEY_PEM", "")
	t.Setenv("GRPC_ENGINE_TLS_SERVER_NAME", "")

	cfg, errConfig := loadConfig()
	if errConfig != nil {
		t.Fatalf("loadConfig returned error for local development: %v", errConfig)
	}
	if cfg.GRPCAddress != "localhost:50051" {
		t.Fatalf("local GRPCAddress = %q, want localhost:50051", cfg.GRPCAddress)
	}
	if cfg.HTTPReadHeaderTimeout != defaultHTTPReadHeaderTimeout || cfg.HTTPReadTimeout != defaultHTTPReadTimeout || cfg.HTTPWriteTimeout != defaultHTTPWriteTimeout || cfg.HTTPIdleTimeout != defaultHTTPIdleTimeout || cfg.HTTPMaxHeaderBytes != defaultHTTPMaxHeaderBytes {
		t.Fatalf("HTTP server defaults = header=%s read=%s write=%s idle=%s max_header=%d", cfg.HTTPReadHeaderTimeout, cfg.HTTPReadTimeout, cfg.HTTPWriteTimeout, cfg.HTTPIdleTimeout, cfg.HTTPMaxHeaderBytes)
	}
}

func TestLoadConfigRejectsInvalidHTTPServerLimits(t *testing.T) {
	for _, test := range []struct {
		name  string
		env   string
		value string
	}{
		{name: "read header timeout too low", env: "HTTP_READ_HEADER_TIMEOUT_MS", value: "0"},
		{name: "read timeout too high", env: "HTTP_READ_TIMEOUT_MS", value: "300001"},
		{name: "write timeout malformed", env: "HTTP_WRITE_TIMEOUT_MS", value: "fast"},
		{name: "idle timeout too low", env: "HTTP_IDLE_TIMEOUT_MS", value: "99"},
		{name: "header bytes too low", env: "HTTP_MAX_HEADER_BYTES", value: "1024"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://local.example/scriptureforge")
			t.Setenv("REDIS_URL", "redis://local.example:6379")
			t.Setenv("DEPLOYMENT_ENVIRONMENT", "development")
			for _, name := range []string{
				"HTTP_READ_HEADER_TIMEOUT_MS",
				"HTTP_READ_TIMEOUT_MS",
				"HTTP_WRITE_TIMEOUT_MS",
				"HTTP_IDLE_TIMEOUT_MS",
				"HTTP_MAX_HEADER_BYTES",
			} {
				t.Setenv(name, "")
			}
			t.Setenv(test.env, test.value)

			cfg, errConfig := loadConfig()
			if errConfig == nil || cfg != nil || !strings.Contains(errConfig.Message, test.env) {
				t.Fatalf("loadConfig = cfg=%#v err=%#v, want %s configuration fault", cfg, errConfig, test.env)
			}
		})
	}
}

func TestHTTPServerAppliesTransportLimits(t *testing.T) {
	cfg := &Config{
		Port:                  "8080",
		HTTPReadHeaderTimeout: 2 * time.Second,
		HTTPReadTimeout:       11 * time.Second,
		HTTPWriteTimeout:      13 * time.Second,
		HTTPIdleTimeout:       17 * time.Second,
		HTTPMaxHeaderBytes:    32 * 1024,
	}
	server := newHTTPServer(cfg, http.NotFoundHandler())
	if server.ReadHeaderTimeout != cfg.HTTPReadHeaderTimeout || server.ReadTimeout != cfg.HTTPReadTimeout || server.WriteTimeout != cfg.HTTPWriteTimeout || server.IdleTimeout != cfg.HTTPIdleTimeout || server.MaxHeaderBytes != cfg.HTTPMaxHeaderBytes {
		t.Fatalf("server transport limits = header=%s read=%s write=%s idle=%s max_header=%d", server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout, server.MaxHeaderBytes)
	}
}

func TestLoadConfigRequiresGRPCAddressInStagingAndProduction(t *testing.T) {
	for _, environment := range []string{"staging", "production", "prod"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "postgres://staging.example/scriptureforge")
			t.Setenv("REDIS_URL", "rediss://staging.example:6379")
			t.Setenv("DEPLOYMENT_ENVIRONMENT", environment)
			t.Setenv("GRPC_ENGINE_ADDRESS", "")
			t.Setenv("GRPC_ENGINE_SHARED_SECRET", "")

			cfg, errConfig := loadConfig()
			if errConfig == nil {
				t.Fatalf("loadConfig returned cfg=%#v, want missing GRPC_ENGINE_ADDRESS error", cfg)
			}
			if errConfig.Category != ConfigurationFault || !strings.Contains(errConfig.Message, "GRPC_ENGINE_ADDRESS") {
				t.Fatalf("loadConfig error = %#v, want GRPC_ENGINE_ADDRESS configuration fault", errConfig)
			}
		})
	}
}

func TestLoadConfigAcceptsExplicitProductionGRPCAddress(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://staging.example/scriptureforge")
	t.Setenv("REDIS_URL", "rediss://staging.example:6379")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "staging")
	t.Setenv("JWT_SECRET_KEY", "jwt-staging-secret-012345678901234567890")
	t.Setenv("JOURNAL_SALT_SECRET", "journal-staging-secret-012345678901234567890")
	t.Setenv("GRPC_ENGINE_ADDRESS", "scriptureforge-rust-engine:50051")
	t.Setenv("GRPC_ENGINE_SHARED_SECRET", "01234567890123456789012345678901")
	t.Setenv("GRPC_ENGINE_TLS_CA_PEM", "test-ca")
	t.Setenv("GRPC_ENGINE_TLS_CLIENT_CERT_PEM", "test-cert")
	t.Setenv("GRPC_ENGINE_TLS_CLIENT_KEY_PEM", "test-key")
	t.Setenv("GRPC_ENGINE_TLS_SERVER_NAME", "scriptureforge-rust-engine")

	cfg, errConfig := loadConfig()
	if errConfig != nil {
		t.Fatalf("loadConfig returned error with explicit GRPC_ENGINE_ADDRESS: %v", errConfig)
	}
	if cfg.GRPCAddress != "scriptureforge-rust-engine:50051" {
		t.Fatalf("GRPCAddress = %q, want scriptureforge-rust-engine:50051", cfg.GRPCAddress)
	}
}

func TestLoadConfigRequiresGRPCSharedSecretAndTLSInProduction(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://staging.example/scriptureforge")
	t.Setenv("REDIS_URL", "rediss://staging.example:6379")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
	t.Setenv("GRPC_ENGINE_ADDRESS", "scriptureforge-rust-engine:50051")
	t.Setenv("GRPC_ENGINE_SHARED_SECRET", "")
	t.Setenv("GRPC_ENGINE_TLS_CA_PEM", "")
	t.Setenv("GRPC_ENGINE_TLS_CLIENT_CERT_PEM", "")
	t.Setenv("GRPC_ENGINE_TLS_CLIENT_KEY_PEM", "")
	t.Setenv("GRPC_ENGINE_TLS_SERVER_NAME", "")

	cfg, errConfig := loadConfig()
	if errConfig == nil || cfg != nil || !strings.Contains(errConfig.Message, "GRPC_ENGINE_SHARED_SECRET") {
		t.Fatalf("loadConfig = cfg=%#v err=%#v, want missing gRPC shared-secret error", cfg, errConfig)
	}
}

func TestLoadConfigRequiresStrongDistinctAuthAndJournalSecretsInProduction(t *testing.T) {
	baseEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv("DATABASE_URL", "postgres://staging.example/scriptureforge")
		t.Setenv("REDIS_URL", "rediss://staging.example:6379")
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
		t.Setenv("GRPC_ENGINE_ADDRESS", "scriptureforge-rust-engine:50051")
		t.Setenv("GRPC_ENGINE_SHARED_SECRET", "01234567890123456789012345678901")
		t.Setenv("GRPC_ENGINE_TLS_CA_PEM", "test-ca")
		t.Setenv("GRPC_ENGINE_TLS_CLIENT_CERT_PEM", "test-cert")
		t.Setenv("GRPC_ENGINE_TLS_CLIENT_KEY_PEM", "test-key")
		t.Setenv("GRPC_ENGINE_TLS_SERVER_NAME", "scriptureforge-rust-engine")
	}

	t.Run("rejects weak jwt secret", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("JWT_SECRET_KEY", "too-short")
		t.Setenv("JOURNAL_SALT_SECRET", "journal-production-secret-012345678901234")
		cfg, errConfig := loadConfig()
		if errConfig == nil || cfg != nil || !strings.Contains(errConfig.Message, "JWT_SECRET_KEY") {
			t.Fatalf("loadConfig = cfg=%#v err=%#v, want weak JWT_SECRET_KEY rejection", cfg, errConfig)
		}
	})

	t.Run("rejects missing journal salt secret", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("JWT_SECRET_KEY", "jwt-production-secret-012345678901234")
		t.Setenv("JOURNAL_SALT_SECRET", "")
		cfg, errConfig := loadConfig()
		if errConfig == nil || cfg != nil || !strings.Contains(errConfig.Message, "JOURNAL_SALT_SECRET") {
			t.Fatalf("loadConfig = cfg=%#v err=%#v, want missing JOURNAL_SALT_SECRET rejection", cfg, errConfig)
		}
	})

	t.Run("rejects key reuse", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("JWT_SECRET_KEY", "same-production-secret-012345678901234")
		t.Setenv("JOURNAL_SALT_SECRET", "same-production-secret-012345678901234")
		cfg, errConfig := loadConfig()
		if errConfig == nil || cfg != nil || !strings.Contains(errConfig.Message, "distinct") {
			t.Fatalf("loadConfig = cfg=%#v err=%#v, want distinct-secret rejection", cfg, errConfig)
		}
	})
}

func TestMountedAuthRoutesEnforceAbuseRateLimit(t *testing.T) {
	t.Setenv("ABUSE_LIMIT_AUTH_REQUESTS", "1")
	t.Setenv("ABUSE_LIMIT_AUTH_WINDOW_SECONDS", "60")
	router := setupRoutes(nil, nil, nil)
	body := `{"email":"member@example.test","password":"password-without-org"}`
	remoteAddr := "198.51.100.10:49152"

	firstStatus, _, firstError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, remoteAddr)
	if firstStatus != http.StatusBadRequest {
		t.Fatalf("first auth request status = %d error = %#v, want validation 400", firstStatus, firstError)
	}

	secondStatus, headers, secondError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, remoteAddr)
	if secondStatus != http.StatusTooManyRequests {
		t.Fatalf("second auth request status = %d error = %#v, want 429", secondStatus, secondError)
	}
	if secondError.Category != "ABUSE_RATE_LIMIT_FAULT" || secondError.Code != http.StatusTooManyRequests {
		t.Fatalf("second auth error = %#v, want abuse rate-limit fault", secondError)
	}
	if headers.Get("Retry-After") == "" || headers.Get("X-RateLimit-Limit") != "1" {
		t.Fatalf("rate-limit headers Retry-After=%q X-RateLimit-Limit=%q", headers.Get("Retry-After"), headers.Get("X-RateLimit-Limit"))
	}

	otherClientStatus, _, otherClientError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, "198.51.100.11:49152")
	if otherClientStatus != http.StatusBadRequest {
		t.Fatalf("other client status = %d error = %#v, want independent validation 400", otherClientStatus, otherClientError)
	}
}

func TestLegacyAuthAliasSharesCanonicalAbuseBucket(t *testing.T) {
	t.Setenv("ABUSE_LIMIT_AUTH_REQUESTS", "1")
	t.Setenv("ABUSE_LIMIT_AUTH_WINDOW_SECONDS", "60")
	router := setupRoutes(nil, nil, nil)
	body := `{"email":"member@example.test","password":"password-without-org"}`
	remoteAddr := "198.51.100.12:49152"

	canonicalStatus, _, canonicalError := exerciseRouteRaw(t, router, "/api/v1/auth/login", body, remoteAddr)
	if canonicalStatus != http.StatusBadRequest {
		t.Fatalf("canonical auth status = %d error = %#v, want validation 400", canonicalStatus, canonicalError)
	}

	legacyStatus, _, legacyError := exerciseRouteRaw(t, router, "/api/auth/login", body, remoteAddr)
	if legacyStatus != http.StatusTooManyRequests {
		t.Fatalf("legacy auth alias status = %d error = %#v, want shared bucket 429", legacyStatus, legacyError)
	}
	if legacyError.Category != "ABUSE_RATE_LIMIT_FAULT" {
		t.Fatalf("legacy auth alias error = %#v, want abuse rate-limit fault", legacyError)
	}
}

func TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles(t *testing.T) {
	tests := []struct {
		name           string
		profileEnvName string
		profileEnvKey  string
		path           string
		method         string
		body           string
		role           string
	}{
		{
			name:           "auth register canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/auth/register",
			method:         http.MethodPost,
			body:           `{"email":"not-an-email","password":"short","organization_id":""}`,
		},
		{
			name:           "auth login canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/auth/login",
			method:         http.MethodPost,
			body:           `{"email":"member@example.test","password":"password-without-org"}`,
		},
		{
			name:           "auth refresh canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/auth/refresh",
			method:         http.MethodPost,
			body:           `{}`,
		},
		{
			name:           "auth logout canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/auth/logout",
			method:         http.MethodPost,
			body:           `{}`,
		},
		{
			name:           "auth mfa verify canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/auth/mfa/verify",
			method:         http.MethodPost,
			body:           `{}`,
		},
		{
			name:           "auth mfa enroll canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/auth/mfa/enroll",
			method:         http.MethodPost,
			role:           "member",
		},
		{
			name:           "auth workspace switch canonical",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/v1/workspaces/switch",
			method:         http.MethodPost,
			body:           `{"organization_id":"test-org-id"}`,
		},
		{
			name:           "auth register legacy alias",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/auth/register",
			method:         http.MethodPost,
			body:           `{"email":"not-an-email","password":"short","organization_id":""}`,
		},
		{
			name:           "auth login legacy alias",
			profileEnvName: abuse.ProfileAuth,
			profileEnvKey:  "ABUSE_LIMIT_AUTH_REQUESTS",
			path:           "/api/auth/login",
			method:         http.MethodPost,
			body:           `{"email":"member@example.test","password":"password-without-org"}`,
		},
		{
			name:           "ai canonical study generation",
			profileEnvName: abuse.ProfileAI,
			profileEnvKey:  "ABUSE_LIMIT_AI_REQUESTS",
			path:           "/api/v1/ai/generate/study",
			method:         http.MethodPost,
		},
		{
			name:           "ai legacy curriculum alias",
			profileEnvName: abuse.ProfileAI,
			profileEnvKey:  "ABUSE_LIMIT_AI_REQUESTS",
			path:           "/api/ai/curriculum",
			method:         http.MethodPost,
		},
		{
			name:           "journal bootstrap",
			profileEnvName: abuse.ProfileJournal,
			profileEnvKey:  "ABUSE_LIMIT_JOURNAL_REQUESTS",
			path:           "/api/v1/journal/bootstrap",
			method:         http.MethodGet,
		},
		{
			name:           "journal list",
			profileEnvName: abuse.ProfileJournal,
			profileEnvKey:  "ABUSE_LIMIT_JOURNAL_REQUESTS",
			path:           "/api/v1/journal_entries",
			method:         http.MethodGet,
		},
		{
			name:           "journal create",
			profileEnvName: abuse.ProfileJournal,
			profileEnvKey:  "ABUSE_LIMIT_JOURNAL_REQUESTS",
			path:           "/api/v1/journal_entries",
			method:         http.MethodPost,
			body:           `{"ciphertext":"cipher","iv":"iv","salt_id":"salt","salt_version":1}`,
		},
		{
			name:           "journal read",
			profileEnvName: abuse.ProfileJournal,
			profileEnvKey:  "ABUSE_LIMIT_JOURNAL_REQUESTS",
			path:           "/api/v1/journal_entries/entry-1",
			method:         http.MethodGet,
		},
		{
			name:           "rooms create",
			profileEnvName: abuse.ProfileRooms,
			profileEnvKey:  "ABUSE_LIMIT_ROOMS_REQUESTS",
			path:           "/api/v1/rooms/create",
			method:         http.MethodPost,
			body:           `{"title":"Rate Limited Room"}`,
		},
		{
			name:           "rooms active",
			profileEnvName: abuse.ProfileRooms,
			profileEnvKey:  "ABUSE_LIMIT_ROOMS_REQUESTS",
			path:           "/api/v1/rooms/active",
			method:         http.MethodGet,
		},
		{
			name:           "rooms state polling",
			profileEnvName: abuse.ProfileRooms,
			profileEnvKey:  "ABUSE_LIMIT_ROOMS_REQUESTS",
			path:           "/api/v1/rooms/state/room-1",
			method:         http.MethodGet,
		},
		{
			name:           "websocket stream",
			profileEnvName: abuse.ProfileWebSocket,
			profileEnvKey:  "ABUSE_LIMIT_WEBSOCKET_REQUESTS",
			path:           "/api/v1/rooms/stream/room-1",
			method:         http.MethodGet,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.profileEnvKey, "1")
			t.Setenv("ABUSE_LIMIT_"+strings.ToUpper(test.profileEnvName)+"_WINDOW_SECONDS", "60")
			t.Setenv("JWT_SECRET_KEY", "route-profile-test-secret-0123456789")
			router := setupRoutes(nil, nil, nil)
			role := test.role
			if role == "" {
				role = "admin"
			}
			token, err := auth.GenerateToken("test-user-id", "test-org-id", role, time.Minute)
			if err != nil {
				t.Fatalf("generate token: %v", err)
			}
			remoteAddr := "192.0.2.10:49152"

			firstStatus, _, firstError := exerciseRouteRawWithMethodAndAuth(t, router, test.path, test.body, remoteAddr, test.method, token)
			if firstStatus == http.StatusTooManyRequests {
				t.Fatalf("%s first status = %d error = %#v, should be below limit", test.name, firstStatus, firstError)
			}

			secondStatus, secondHeaders, secondError := exerciseRouteRawWithMethodAndAuth(t, router, test.path, test.body, remoteAddr, test.method, token)
			if secondStatus != http.StatusTooManyRequests {
				t.Fatalf("%s second status = %d error = %#v, want 429", test.name, secondStatus, secondError)
			}
			if secondError.Category != "ABUSE_RATE_LIMIT_FAULT" || secondError.Code != http.StatusTooManyRequests {
				t.Fatalf("%s second error = %#v, want abuse rate-limit fault", test.name, secondError)
			}
			if got := secondHeaders.Get("Retry-After"); got == "" {
				t.Fatalf("%s missing Retry-After header", test.name)
			}
			if limit := secondHeaders.Get("X-RateLimit-Limit"); limit != "1" {
				t.Fatalf("%s X-RateLimit-Limit=%q, want 1", test.name, limit)
			}
			if remaining := secondHeaders.Get("X-RateLimit-Remaining"); remaining != "0" {
				t.Fatalf("%s X-RateLimit-Remaining=%q, want 0", test.name, remaining)
			}
			if reset := secondHeaders.Get("X-RateLimit-Reset"); reset == "" {
				t.Fatalf("%s missing X-RateLimit-Reset header", test.name)
			}
		})
	}
}

func TestWorkspaceSwitchRouteEnforcesOrgMatch(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "route-workspace-switch-secret-0123456789")
	orgID := "55555555-5555-4555-8555-555555555555"
	router := setupRoutes(nil, nil, nil)
	token, err := auth.GenerateToken("member-user-id", orgID, "member", time.Minute)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/switch", strings.NewReader(`{"organization_id":"`+orgID+`"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, request)
	if allowed.Code != http.StatusOK {
		t.Fatalf("/api/v1/workspaces/switch status = %d body = %q", allowed.Code, allowed.Body.String())
	}

	requestMismatch := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces/switch", strings.NewReader(`{"organization_id":"55555555-0000-4555-8555-555555555555"}`))
	requestMismatch.Header.Set("Authorization", "Bearer "+token)
	forbidden := httptest.NewRecorder()
	router.ServeHTTP(forbidden, requestMismatch)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("workspace switch mismatch status = %d body = %q", forbidden.Code, forbidden.Body.String())
	}
}

func exerciseRouteRawWithMethodAndAuth(t *testing.T, handler http.Handler, path string, body string, remoteAddr string, method string, token string) (int, http.Header, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), response
}

func exerciseRouteRawWithMethod(t *testing.T, handler http.Handler, path string, body string, remoteAddr string, method string) (int, http.Header, auth.PlatformException) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	handler.ServeHTTP(recorder, request)

	var response auth.PlatformException
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode %s response %d %q: %v", path, recorder.Code, recorder.Body.String(), err)
	}
	return recorder.Code, recorder.Header(), response
}
