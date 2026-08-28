package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"scriptureforge/internal/adapters/integration_zoom"
	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/abuse"
	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
	"scriptureforge/internal/domain/room"
	"scriptureforge/internal/ports"
)

type ErrorCategory string

const (
	AIOrchestrationEngineFault ErrorCategory = "AI_ORCHESTRATION_ENGINE_FAULT"
	DatabaseConnectionFault    ErrorCategory = "DATABASE_CONNECTION_FAULT"
	CacheConnectionFault       ErrorCategory = "CACHE_CONNECTION_FAULT"
	ConfigurationFault         ErrorCategory = "CONFIGURATION_FAULT"

	defaultHTTPReadHeaderTimeout = 5 * time.Second
	defaultHTTPReadTimeout       = 30 * time.Second
	defaultHTTPWriteTimeout      = 30 * time.Second
	defaultHTTPIdleTimeout       = 60 * time.Second
	defaultHTTPMaxHeaderBytes    = 1 << 20
	minHTTPTimeout               = 100 * time.Millisecond
	maxHTTPReadHeaderTimeout     = 120 * time.Second
	maxHTTPReadWriteTimeout      = 5 * time.Minute
	maxHTTPIdleTimeout           = 10 * time.Minute
	minHTTPMaxHeaderBytes        = 4 << 10
	maxHTTPMaxHeaderBytes        = 16 << 20

	defaultStartupDependencyTimeout = 10 * time.Second
	minStartupDependencyTimeout     = time.Second
	maxStartupDependencyTimeout     = time.Minute
	defaultDatabasePoolMaxConns     = int32(10)
	defaultDatabasePoolMinConns     = int32(0)
	minDatabasePoolMaxConns         = int64(1)
	maxDatabasePoolMaxConns         = int64(100)
	minDatabasePoolMinConns         = int64(0)
	maxDatabasePoolMinConns         = int64(50)
	defaultDatabaseConnLifetime     = 30 * time.Minute
	defaultDatabaseConnIdleTime     = 5 * time.Minute
	minDatabaseConnLifecycle        = time.Minute
	maxDatabaseConnLifecycle        = 24 * time.Hour
	defaultRedisPoolSize            = 10
	defaultRedisMaxActiveConns      = 10
	minRedisPoolSize                = int64(1)
	maxRedisPoolSize                = int64(100)
	minRedisMaxActiveConns          = int64(1)
	maxRedisMaxActiveConns          = int64(100)
	defaultRedisPoolTimeout         = 5 * time.Second
	defaultRedisDialTimeout         = 5 * time.Second
	defaultRedisReadTimeout         = 3 * time.Second
	defaultRedisWriteTimeout        = 3 * time.Second
	minRedisTimeout                 = 100 * time.Millisecond
	maxRedisTimeout                 = time.Minute
)

type PlatformException struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Code     int           `json:"code"`
	TraceID  string        `json:"trace_id"`
}

func (e *PlatformException) Error() string {
	return fmt.Sprintf("[%s] %s (Trace: %s)", e.Category, e.Message, e.TraceID)
}

type Config struct {
	DatabaseURL              string
	RedisURL                 string
	RedisPassword            string
	Port                     string
	StartupDependencyTimeout time.Duration
	DatabasePoolMaxConns     int32
	DatabasePoolMinConns     int32
	DatabaseConnLifetime     time.Duration
	DatabaseConnIdleTime     time.Duration
	RedisPoolSize            int
	RedisMaxActiveConns      int
	RedisPoolTimeout         time.Duration
	RedisDialTimeout         time.Duration
	RedisReadTimeout         time.Duration
	RedisWriteTimeout        time.Duration
	HTTPReadHeaderTimeout    time.Duration
	HTTPReadTimeout          time.Duration
	HTTPWriteTimeout         time.Duration
	HTTPIdleTimeout          time.Duration
	HTTPMaxHeaderBytes       int
	APIRequestTimeout        time.Duration
	ShutdownTimeout          time.Duration
	GRPCAddress              string
	GRPCSharedSecret         string
	GRPCTLSCAPEM             string
	GRPCTLSClientCertificate string
	GRPCTLSClientKey         string
	GRPCTLSServerName        string
}

func loadConfig() (*Config, *PlatformException) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, &PlatformException{
			Category: ConfigurationFault,
			Message:  "DATABASE_URL environment variable is missing",
			Code:     500,
		}
	}
	if err := validateDatabaseURLTransport(dbURL, requiresConfiguredGRPCAddress()); err != nil {
		return nil, &PlatformException{
			Category: ConfigurationFault,
			Message:  err.Error(),
			Code:     500,
		}
	}

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return nil, &PlatformException{
			Category: ConfigurationFault,
			Message:  "REDIS_URL environment variable is missing",
			Code:     500,
		}
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	if requiresConfiguredGRPCAddress() && strings.TrimSpace(redisPassword) == "" {
		return nil, &PlatformException{
			Category: ConfigurationFault,
			Message:  "REDIS_PASSWORD environment variable is required in non-local environments",
			Code:     500,
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	httpConfig, httpConfigErr := loadHTTPServerConfig()
	if httpConfigErr != nil {
		return nil, httpConfigErr
	}
	dependencyConfig, dependencyConfigErr := loadDependencyConfig()
	if dependencyConfigErr != nil {
		return nil, dependencyConfigErr
	}

	grpcAddr := os.Getenv("GRPC_ENGINE_ADDRESS")
	if grpcAddr == "" {
		if requiresConfiguredGRPCAddress() {
			return nil, &PlatformException{
				Category: ConfigurationFault,
				Message:  "GRPC_ENGINE_ADDRESS environment variable is required in staging/production",
				Code:     500,
			}
		}
		grpcAddr = "localhost:50051"
	}

	grpcSharedSecret := strings.TrimSpace(os.Getenv("GRPC_ENGINE_SHARED_SECRET"))
	grpcTLSCAPEM := os.Getenv("GRPC_ENGINE_TLS_CA_PEM")
	grpcTLSClientCertificate := os.Getenv("GRPC_ENGINE_TLS_CLIENT_CERT_PEM")
	grpcTLSClientKey := os.Getenv("GRPC_ENGINE_TLS_CLIENT_KEY_PEM")
	grpcTLSServerName := strings.TrimSpace(os.Getenv("GRPC_ENGINE_TLS_SERVER_NAME"))
	if requiresConfiguredGRPCAddress() {
		if len(grpcSharedSecret) < 32 {
			return nil, &PlatformException{
				Category: ConfigurationFault,
				Message:  "GRPC_ENGINE_SHARED_SECRET must be at least 32 bytes in staging/production",
				Code:     500,
			}
		}
		for name, value := range map[string]string{
			"GRPC_ENGINE_TLS_CA_PEM":          grpcTLSCAPEM,
			"GRPC_ENGINE_TLS_CLIENT_CERT_PEM": grpcTLSClientCertificate,
			"GRPC_ENGINE_TLS_CLIENT_KEY_PEM":  grpcTLSClientKey,
			"GRPC_ENGINE_TLS_SERVER_NAME":     grpcTLSServerName,
		} {
			if strings.TrimSpace(value) == "" {
				return nil, &PlatformException{
					Category: ConfigurationFault,
					Message:  name + " environment variable is required in staging/production",
					Code:     500,
				}
			}
		}
	}

	if requiresConfiguredGRPCAddress() {
		jwtSecret := os.Getenv("JWT_SECRET_KEY")
		journalSaltSecret := os.Getenv("JOURNAL_SALT_SECRET")
		for name, value := range map[string]string{
			"JWT_SECRET_KEY":      jwtSecret,
			"JOURNAL_SALT_SECRET": journalSaltSecret,
		} {
			if err := auth.ValidateSecretStrength(name, value); err != nil {
				return nil, &PlatformException{Category: ConfigurationFault, Message: err.Error() + " in staging/production", Code: 500}
			}
		}
		if jwtSecret == journalSaltSecret {
			return nil, &PlatformException{
				Category: ConfigurationFault,
				Message:  "JOURNAL_SALT_SECRET must be distinct from JWT_SECRET_KEY in staging/production",
				Code:     500,
			}
		}
	}
	if _, originConfigErr := loadAllowedBrowserOrigins(); originConfigErr != nil {
		return nil, originConfigErr
	}

	return &Config{
		DatabaseURL:              dbURL,
		RedisURL:                 redisURL,
		RedisPassword:            redisPassword,
		Port:                     port,
		StartupDependencyTimeout: dependencyConfig.StartupTimeout,
		DatabasePoolMaxConns:     dependencyConfig.DatabasePoolMaxConns,
		DatabasePoolMinConns:     dependencyConfig.DatabasePoolMinConns,
		DatabaseConnLifetime:     dependencyConfig.DatabaseConnLifetime,
		DatabaseConnIdleTime:     dependencyConfig.DatabaseConnIdleTime,
		RedisPoolSize:            dependencyConfig.RedisPoolSize,
		RedisMaxActiveConns:      dependencyConfig.RedisMaxActiveConns,
		RedisPoolTimeout:         dependencyConfig.RedisPoolTimeout,
		RedisDialTimeout:         dependencyConfig.RedisDialTimeout,
		RedisReadTimeout:         dependencyConfig.RedisReadTimeout,
		RedisWriteTimeout:        dependencyConfig.RedisWriteTimeout,
		HTTPReadHeaderTimeout:    httpConfig.ReadHeaderTimeout,
		HTTPReadTimeout:          httpConfig.ReadTimeout,
		HTTPWriteTimeout:         httpConfig.WriteTimeout,
		HTTPIdleTimeout:          httpConfig.IdleTimeout,
		HTTPMaxHeaderBytes:       httpConfig.MaxHeaderBytes,
		APIRequestTimeout:        httpConfig.APIRequestTimeout,
		ShutdownTimeout:          httpConfig.ShutdownTimeout,
		GRPCAddress:              grpcAddr,
		GRPCSharedSecret:         grpcSharedSecret,
		GRPCTLSCAPEM:             grpcTLSCAPEM,
		GRPCTLSClientCertificate: grpcTLSClientCertificate,
		GRPCTLSClientKey:         grpcTLSClientKey,
		GRPCTLSServerName:        grpcTLSServerName,
	}, nil
}

type dependencyConfig struct {
	StartupTimeout       time.Duration
	DatabasePoolMaxConns int32
	DatabasePoolMinConns int32
	DatabaseConnLifetime time.Duration
	DatabaseConnIdleTime time.Duration
	RedisPoolSize        int
	RedisMaxActiveConns  int
	RedisPoolTimeout     time.Duration
	RedisDialTimeout     time.Duration
	RedisReadTimeout     time.Duration
	RedisWriteTimeout    time.Duration
}

func loadDependencyConfig() (dependencyConfig, *PlatformException) {
	startupTimeout, err := loadDurationMilliseconds("STARTUP_DEPENDENCY_TIMEOUT_MS", defaultStartupDependencyTimeout, minStartupDependencyTimeout, maxStartupDependencyTimeout)
	if err != nil {
		return dependencyConfig{}, err
	}
	databasePoolMaxConns, err := loadInteger("DB_POOL_MAX_CONNS", int64(defaultDatabasePoolMaxConns), minDatabasePoolMaxConns, maxDatabasePoolMaxConns)
	if err != nil {
		return dependencyConfig{}, err
	}
	databasePoolMinConns, err := loadInteger("DB_POOL_MIN_CONNS", int64(defaultDatabasePoolMinConns), minDatabasePoolMinConns, maxDatabasePoolMinConns)
	if err != nil {
		return dependencyConfig{}, err
	}
	if databasePoolMinConns > databasePoolMaxConns {
		return dependencyConfig{}, configurationFault("DB_POOL_MIN_CONNS must not exceed DB_POOL_MAX_CONNS")
	}
	databaseConnLifetime, err := loadDurationMilliseconds("DB_POOL_MAX_CONN_LIFETIME_MS", defaultDatabaseConnLifetime, minDatabaseConnLifecycle, maxDatabaseConnLifecycle)
	if err != nil {
		return dependencyConfig{}, err
	}
	databaseConnIdleTime, err := loadDurationMilliseconds("DB_POOL_MAX_CONN_IDLE_TIME_MS", defaultDatabaseConnIdleTime, minDatabaseConnLifecycle, maxDatabaseConnLifecycle)
	if err != nil {
		return dependencyConfig{}, err
	}
	redisPoolSize, err := loadInteger("REDIS_POOL_SIZE", int64(defaultRedisPoolSize), minRedisPoolSize, maxRedisPoolSize)
	if err != nil {
		return dependencyConfig{}, err
	}
	redisMaxActiveConns, err := loadInteger("REDIS_MAX_ACTIVE_CONNS", int64(defaultRedisMaxActiveConns), minRedisMaxActiveConns, maxRedisMaxActiveConns)
	if err != nil {
		return dependencyConfig{}, err
	}
	if redisMaxActiveConns < redisPoolSize {
		return dependencyConfig{}, configurationFault("REDIS_MAX_ACTIVE_CONNS must not be less than REDIS_POOL_SIZE")
	}
	redisPoolTimeout, err := loadDurationMilliseconds("REDIS_POOL_TIMEOUT_MS", defaultRedisPoolTimeout, minRedisTimeout, maxRedisTimeout)
	if err != nil {
		return dependencyConfig{}, err
	}
	redisDialTimeout, err := loadDurationMilliseconds("REDIS_DIAL_TIMEOUT_MS", defaultRedisDialTimeout, minRedisTimeout, maxRedisTimeout)
	if err != nil {
		return dependencyConfig{}, err
	}
	redisReadTimeout, err := loadDurationMilliseconds("REDIS_READ_TIMEOUT_MS", defaultRedisReadTimeout, minRedisTimeout, maxRedisTimeout)
	if err != nil {
		return dependencyConfig{}, err
	}
	redisWriteTimeout, err := loadDurationMilliseconds("REDIS_WRITE_TIMEOUT_MS", defaultRedisWriteTimeout, minRedisTimeout, maxRedisTimeout)
	if err != nil {
		return dependencyConfig{}, err
	}
	return dependencyConfig{
		StartupTimeout:       startupTimeout,
		DatabasePoolMaxConns: int32(databasePoolMaxConns),
		DatabasePoolMinConns: int32(databasePoolMinConns),
		DatabaseConnLifetime: databaseConnLifetime,
		DatabaseConnIdleTime: databaseConnIdleTime,
		RedisPoolSize:        int(redisPoolSize),
		RedisMaxActiveConns:  int(redisMaxActiveConns),
		RedisPoolTimeout:     redisPoolTimeout,
		RedisDialTimeout:     redisDialTimeout,
		RedisReadTimeout:     redisReadTimeout,
		RedisWriteTimeout:    redisWriteTimeout,
	}, nil
}

func loadInteger(name string, defaultValue, minValue, maxValue int64) (int64, *PlatformException) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minValue || value > maxValue {
		return 0, configurationFault(fmt.Sprintf("%s must be an integer between %d and %d", name, minValue, maxValue))
	}
	return value, nil
}

func loadDurationMilliseconds(name string, defaultValue, minValue, maxValue time.Duration) (time.Duration, *PlatformException) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return defaultValue, nil
	}
	millis, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || millis < minValue.Milliseconds() || millis > maxValue.Milliseconds() {
		return 0, configurationFault(fmt.Sprintf("%s must be an integer between %d and %d milliseconds", name, minValue.Milliseconds(), maxValue.Milliseconds()))
	}
	return time.Duration(millis) * time.Millisecond, nil
}

func configurationFault(message string) *PlatformException {
	return &PlatformException{Category: ConfigurationFault, Message: message, Code: http.StatusInternalServerError}
}

func newDatabasePoolConfig(cfg *Config) (*pgxpool.Config, error) {
	dbConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	dbConfig.MaxConns = cfg.DatabasePoolMaxConns
	dbConfig.MinConns = cfg.DatabasePoolMinConns
	dbConfig.MaxConnLifetime = cfg.DatabaseConnLifetime
	dbConfig.MaxConnIdleTime = cfg.DatabaseConnIdleTime
	dbConfig.ConnConfig.ConnectTimeout = cfg.StartupDependencyTimeout
	return dbConfig, nil
}

func newRedisOptions(cfg *Config) (*redis.Options, error) {
	options, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.RedisPassword) != "" {
		options.Password = cfg.RedisPassword
	}
	options.PoolSize = cfg.RedisPoolSize
	options.MaxActiveConns = cfg.RedisMaxActiveConns
	options.PoolTimeout = cfg.RedisPoolTimeout
	options.DialTimeout = cfg.RedisDialTimeout
	options.ReadTimeout = cfg.RedisReadTimeout
	options.WriteTimeout = cfg.RedisWriteTimeout
	return options, nil
}

type httpServerConfig struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	APIRequestTimeout time.Duration
	ShutdownTimeout   time.Duration
}

func loadHTTPServerConfig() (httpServerConfig, *PlatformException) {
	readHeaderTimeout, err := loadHTTPTimeout("HTTP_READ_HEADER_TIMEOUT_MS", defaultHTTPReadHeaderTimeout, minHTTPTimeout, maxHTTPReadHeaderTimeout)
	if err != nil {
		return httpServerConfig{}, err
	}
	readTimeout, err := loadHTTPTimeout("HTTP_READ_TIMEOUT_MS", defaultHTTPReadTimeout, minHTTPTimeout, maxHTTPReadWriteTimeout)
	if err != nil {
		return httpServerConfig{}, err
	}
	writeTimeout, err := loadHTTPTimeout("HTTP_WRITE_TIMEOUT_MS", defaultHTTPWriteTimeout, minHTTPTimeout, maxHTTPReadWriteTimeout)
	if err != nil {
		return httpServerConfig{}, err
	}
	idleTimeout, err := loadHTTPTimeout("HTTP_IDLE_TIMEOUT_MS", defaultHTTPIdleTimeout, minHTTPTimeout, maxHTTPIdleTimeout)
	if err != nil {
		return httpServerConfig{}, err
	}
	maxHeaderBytes, err := loadHTTPMaxHeaderBytes()
	if err != nil {
		return httpServerConfig{}, err
	}
	apiRequestTimeout, err := loadHTTPTimeout("API_REQUEST_TIMEOUT_MS", defaultAPIRequestTimeout, minAPIRequestTimeout, maxAPIRequestTimeout)
	if err != nil {
		return httpServerConfig{}, err
	}
	shutdownTimeout, err := loadHTTPTimeout("SHUTDOWN_TIMEOUT_MS", defaultShutdownTimeout, minShutdownTimeout, maxShutdownTimeout)
	if err != nil {
		return httpServerConfig{}, err
	}
	return httpServerConfig{
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		APIRequestTimeout: apiRequestTimeout,
		ShutdownTimeout:   shutdownTimeout,
	}, nil
}

func loadHTTPTimeout(name string, defaultValue, minValue, maxValue time.Duration) (time.Duration, *PlatformException) {
	return loadDurationMilliseconds(name, defaultValue, minValue, maxValue)
}

func loadHTTPMaxHeaderBytes() (int, *PlatformException) {
	raw := strings.TrimSpace(os.Getenv("HTTP_MAX_HEADER_BYTES"))
	if raw == "" {
		return defaultHTTPMaxHeaderBytes, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minHTTPMaxHeaderBytes || value > maxHTTPMaxHeaderBytes {
		return 0, &PlatformException{
			Category: ConfigurationFault,
			Message:  fmt.Sprintf("HTTP_MAX_HEADER_BYTES must be an integer between %d and %d bytes", minHTTPMaxHeaderBytes, maxHTTPMaxHeaderBytes),
			Code:     http.StatusInternalServerError,
		}
	}
	return int(value), nil
}

func requiresConfiguredGRPCAddress() bool {
	return requiresConfiguredGRPCAddressForEnvironment(os.Getenv("DEPLOYMENT_ENVIRONMENT"))
}

func requiresConfiguredGRPCAddressForEnvironment(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "staging", "production", "prod":
		return true
	case "", "development", "dev", "test", "local":
		return false
	default:
		return true
	}
}

func validateDatabaseURLTransport(rawURL string, requireTLS bool) error {
	if !requireTLS {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		return fmt.Errorf("DATABASE_URL must be a valid PostgreSQL URL with TLS in staging/production")
	}
	values := parsed.Query()["sslmode"]
	if len(values) != 1 {
		return fmt.Errorf("DATABASE_URL must set sslmode=require, verify-ca, or verify-full in staging/production")
	}
	switch strings.ToLower(strings.TrimSpace(values[0])) {
	case "require", "verify-ca", "verify-full":
		return nil
	default:
		return fmt.Errorf("DATABASE_URL must set sslmode=require, verify-ca, or verify-full in staging/production")
	}
}

func setupRoutes(dbpool *pgxpool.Pool, vectorDB ai.VectorDB, redisClient *redis.Client) http.Handler {
	return setupRoutesWithTimeout(dbpool, vectorDB, redisClient, defaultAPIRequestTimeout)
}

func setupRoutesWithTimeout(dbpool *pgxpool.Pool, vectorDB ai.VectorDB, redisClient *redis.Client, apiRequestTimeout time.Duration) http.Handler {
	return setupRoutesWithLifecycle(dbpool, vectorDB, redisClient, apiRequestTimeout, nil)
}

func setupRoutesWithLifecycle(dbpool *pgxpool.Pool, vectorDB ai.VectorDB, redisClient *redis.Client, apiRequestTimeout time.Duration, lifecycle *serverLifecycle) http.Handler {
	mux := http.ServeMux{}
	abuseLimiter := abuse.NewDefaultRedisLimiter(redisClient)
	observer := observability.NewDefaultObserver()
	mux.HandleFunc("/live", liveHandler)
	mux.HandleFunc("/ready", readyHandlerWithLifecycle(dbpool, redisClient, vectorDB, lifecycle))
	mux.Handle("/metrics", protectedMetricsHandler(observer.MetricsHandler()))

	// Auth Endpoints
	authHandler := &ports.AuthHandler{DB: dbpool, AccountLimiter: abuseLimiter, MFAEncryptionKey: []byte(os.Getenv("MFA_ENCRYPTION_KEY"))}
	var sessionValidator auth.SessionValidator
	if dbpool != nil {
		sessionValidator = authHandler.ValidateActiveSession
	}
	protected := func(next http.Handler, requiredRole string) http.Handler {
		return auth.RBACMiddlewareWithSession(next, requiredRole, sessionValidator)
	}
	protectedAnyRole := func(next http.Handler, requiredRoles ...string) http.Handler {
		return auth.RBACMiddlewareAnyRoleWithSession(next, sessionValidator, requiredRoles...)
	}
	mux.Handle("/api/v1/auth/csrf", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(csrfHandler)))
	mux.Handle("/api/v1/auth/register", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.RegisterHandler)))
	mux.Handle("/api/v1/auth/login", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.LoginHandler)))
	mux.Handle("/api/v1/auth/refresh", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.RefreshHandler)))
	mux.Handle("/api/v1/auth/logout", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.LogoutHandler)))
	mux.Handle("/api/v1/auth/mfa/verify", protected(abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.MFAVerifyHandler)), ""))
	mux.Handle("/api/v1/auth/mfa/enroll", protected(abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.MFAEnrollHandler)), ""))
	mux.Handle("/api/v1/workspaces/switch", protected(abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.WorkspaceSwitchHandler)), ""))
	mux.Handle("/api/auth/register", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.RegisterHandler)))
	mux.Handle("/api/auth/login", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.LoginHandler)))

	journalHandler := &ports.JournalHandler{DB: dbpool}
	mux.Handle("/api/v1/journal/bootstrap", protected(abuseLimiter.Middleware(abuse.ProfileJournal, http.HandlerFunc(journalHandler.ServeJournalBootstrap)), ""))
	mux.Handle("/api/v1/journal_entries", protected(abuseLimiter.Middleware(abuse.ProfileJournal, http.HandlerFunc(journalHandler.ServeJournalEntries)), ""))
	mux.Handle("/api/v1/journal_entries/", protected(abuseLimiter.Middleware(abuse.ProfileJournal, http.HandlerFunc(journalHandler.ServeJournalEntry)), ""))

	// AI Endpoints (Protected by RBAC)
	ragEngine := ai.NewRAGEngine(vectorDB)
	mapReduceWorker := ai.NewMapReduceWorker(4000)

	aiHandler := &ports.AIHandler{
		DB:              dbpool,
		RAGEngine:       ragEngine,
		Verifier:        ai.NewResponseVerificationSubsystem(),
		LLMClient:       llm.NewLLMClient(),
		MapReduceWorker: mapReduceWorker,
	}
	aiHandle := abuseLimiter.Middleware(abuse.ProfileAI, http.HandlerFunc(aiHandler.GenerateCurriculumHandler))
	mux.Handle("/api/v1/ai/generate/study", protectedAnyRole(aiHandle, "moderator", "author"))
	mux.Handle("/api/ai/curriculum", protectedAnyRole(aiHandle, "moderator", "author"))

	// Room & Zoom Webhook Initialization
	roomStateManager := room.NewRoomStateManager(redisClient)
	roomHub := ports.NewRedisRoomHub(redisClient)
	roomHandler := &ports.RoomHandler{
		DB:              dbpool,
		StateManager:    roomStateManager,
		MeetingAdapter:  integration_zoom.NewZoomClient(),
		MeetingProvider: "zoom",
	}
	mux.Handle("/api/v1/rooms/create", protected(abuseLimiter.Middleware(abuse.ProfileRooms, http.HandlerFunc(roomHandler.CreateRoomHandler)), "moderator"))
	mux.Handle("/api/v1/rooms/active", protected(abuseLimiter.Middleware(abuse.ProfileRooms, http.HandlerFunc(roomHandler.ActiveRoomsHandler)), ""))
	mux.Handle("/api/v1/rooms/state/", protected(abuseLimiter.Middleware(abuse.ProfileRooms, http.HandlerFunc(roomHandler.RoomStateHandler)), ""))

	zoomWebhookHandler := integration_zoom.NewWebhookHandler(roomStateManager, dbpool)
	mux.Handle("/api/webhooks/zoom", abuseLimiter.Middleware(abuse.ProfileZoomWebhook, http.HandlerFunc(zoomWebhookHandler.HandleZoomWebhook)))

	// Websockets (Protected)
	socketConn := &ports.SocketConnection{
		DB:                dbpool,
		StateManager:      roomStateManager,
		Hub:               roomHub,
		ConnectionLimiter: abuse.NewDefaultRedisActiveConnectionLimiter(redisClient),
	}
	if lifecycle != nil {
		lifecycle.onShutdown = socketConn.BeginShutdown
	}
	mux.Handle("/api/v1/rooms/stream/", protected(abuseLimiter.Middleware(abuse.ProfileWebSocket, http.HandlerFunc(socketConn.HandleLiveRoom)), ""))

	return apiRequestDeadlineMiddleware(apiSecurityMiddleware(observer.Middleware(&mux)), apiRequestTimeout)
}

func liveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func readyHandler(dbpool *pgxpool.Pool, redisClient *redis.Client, vectorDB ai.VectorDB) http.HandlerFunc {
	return readyHandlerWithLifecycle(dbpool, redisClient, vectorDB, nil)
}

func readyHandlerWithLifecycle(dbpool *pgxpool.Pool, redisClient *redis.Client, vectorDB ai.VectorDB, lifecycle *serverLifecycle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if lifecycle.isDraining() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unready","reason":"server_draining"}`))
			return
		}
		if dbpool == nil || redisClient == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unready","reason":"dependencies_not_configured"}`))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := dbpool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unready","reason":"database_unavailable"}`))
			return
		}
		if err := redisClient.Ping(ctx).Err(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unready","reason":"redis_unavailable"}`))
			return
		}
		if requiresConfiguredGRPCAddress() {
			checker, ok := vectorDB.(ai.ReadinessChecker)
			if !ok {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"unready","reason":"scripture_engine_readiness_unavailable"}`))
				return
			}
			if err := checker.CheckReadiness(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"status":"unready","reason":"scripture_engine_unavailable"}`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, errConfig := loadConfig()
	if errConfig != nil {
		log.Fatalf("Initialization failed: %v", errConfig)
	}
	shutdownOTel, err := observability.InitOpenTelemetry(ctx, observability.OTelConfigFromEnv())
	if err != nil {
		log.Fatalf("OpenTelemetry initialization failed: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := shutdownOTel(shutdownCtx); err != nil {
			log.Printf("OpenTelemetry shutdown failed: %v", err)
		}
	}()

	dbConfig, err := newDatabasePoolConfig(cfg)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	dbConfig.MaxConns = cfg.DatabasePoolMaxConns
	dbConfig.MinConns = cfg.DatabasePoolMinConns
	dbConfig.MaxConnLifetime = cfg.DatabaseConnLifetime
	dbConfig.MaxConnIdleTime = cfg.DatabaseConnIdleTime
	dbConfig.ConnConfig.ConnectTimeout = cfg.StartupDependencyTimeout
	dbpool, err := pgxpool.NewWithConfig(ctx, dbConfig)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer dbpool.Close()

	dependencyCtx, dependencyCancel := context.WithTimeout(ctx, cfg.StartupDependencyTimeout)
	defer dependencyCancel()
	if err := dbpool.Ping(dependencyCtx); err != nil {
		log.Fatalf("Database ping failed: %v", err)
	}
	log.Println("Successfully connected to PostgreSQL pool.")

	opt, err := newRedisOptions(cfg)
	if err != nil {
		log.Fatalf("Redis initialization failed: %v", err)
	}

	rdb := redis.NewClient(opt)
	defer rdb.Close()

	if err := rdb.Ping(dependencyCtx).Err(); err != nil {
		log.Fatalf("Redis ping failed: %v", err)
	}
	log.Println("Successfully connected to Redis pool.")

	var vectorDB ai.VectorDB
	vectorClient, err := ai.NewGRPCScriptureClientWithConfig(
		cfg.GRPCAddress,
		cfg.GRPCSharedSecret,
		cfg.GRPCTLSCAPEM,
		cfg.GRPCTLSClientCertificate,
		cfg.GRPCTLSClientKey,
		cfg.GRPCTLSServerName,
	)
	if err != nil {
		log.Printf("Warning: Failed to connect to Rust gRPC Scripture Engine at %s: %v. AI features will fail.", cfg.GRPCAddress, err)
		vectorDB = ai.UnavailableVectorDB{Reason: "Rust gRPC Scripture Engine is unavailable"}
	} else {
		defer vectorClient.Close()
		vectorDB = vectorClient
		log.Println("Successfully connected to Rust gRPC Scripture Engine.")
	}

	lifecycle := &serverLifecycle{}
	router := setupRoutesWithLifecycle(dbpool, vectorDB, rdb, cfg.APIRequestTimeout, lifecycle)
	server := newHTTPServer(cfg, router)
	server.RegisterOnShutdown(lifecycle.beginShutdown)

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Server listening on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	select {
	case <-quit:
		log.Println("Received termination signal. Initiating graceful shutdown...")
	case err := <-serverErrors:
		lifecycle.beginShutdown()
		log.Printf("HTTP server stopped unexpectedly: %v", err)
		return
	}

	lifecycle.beginShutdown()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
		return
	}

	log.Println("Shutdown complete.")
}

func newHTTPServer(cfg *Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    cfg.HTTPMaxHeaderBytes,
	}
}
