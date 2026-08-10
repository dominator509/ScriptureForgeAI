package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	Port                     string
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

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return nil, &PlatformException{
			Category: ConfigurationFault,
			Message:  "REDIS_URL environment variable is missing",
			Code:     500,
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
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

	return &Config{
		DatabaseURL:              dbURL,
		RedisURL:                 redisURL,
		Port:                     port,
		GRPCAddress:              grpcAddr,
		GRPCSharedSecret:         grpcSharedSecret,
		GRPCTLSCAPEM:             grpcTLSCAPEM,
		GRPCTLSClientCertificate: grpcTLSClientCertificate,
		GRPCTLSClientKey:         grpcTLSClientKey,
		GRPCTLSServerName:        grpcTLSServerName,
	}, nil
}

func requiresConfiguredGRPCAddress() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOYMENT_ENVIRONMENT"))) {
	case "staging", "production", "prod":
		return true
	default:
		return false
	}
}

func setupRoutes(dbpool *pgxpool.Pool, vectorDB ai.VectorDB, redisClient *redis.Client) http.Handler {
	mux := http.ServeMux{}
	abuseLimiter := abuse.NewDefaultLimiter()
	observer := observability.NewDefaultObserver()
	mux.HandleFunc("/live", liveHandler)
	mux.HandleFunc("/ready", readyHandler(dbpool, redisClient))
	mux.Handle("/metrics", observer.MetricsHandler())

	// Auth Endpoints
	authHandler := &ports.AuthHandler{DB: dbpool, AccountLimiter: abuseLimiter}
	mux.Handle("/api/v1/auth/register", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.RegisterHandler)))
	mux.Handle("/api/v1/auth/login", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.LoginHandler)))
	mux.Handle("/api/v1/auth/refresh", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.RefreshHandler)))
	mux.Handle("/api/v1/auth/logout", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.LogoutHandler)))
	mux.Handle("/api/v1/auth/mfa/verify", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.MFAVerifyHandler)), ""))
	mux.Handle("/api/v1/auth/mfa/enroll", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.MFAEnrollHandler)), ""))
	mux.Handle("/api/v1/workspaces/switch", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.WorkspaceSwitchHandler)), ""))
	mux.Handle("/api/auth/register", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.RegisterHandler)))
	mux.Handle("/api/auth/login", abuseLimiter.Middleware(abuse.ProfileAuth, http.HandlerFunc(authHandler.LoginHandler)))

	journalHandler := &ports.JournalHandler{DB: dbpool}
	mux.Handle("/api/v1/journal/bootstrap", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileJournal, http.HandlerFunc(journalHandler.ServeJournalBootstrap)), ""))
	mux.Handle("/api/v1/journal_entries", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileJournal, http.HandlerFunc(journalHandler.ServeJournalEntries)), ""))
	mux.Handle("/api/v1/journal_entries/", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileJournal, http.HandlerFunc(journalHandler.ServeJournalEntry)), ""))

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
	mux.Handle("/api/v1/ai/generate/study", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileAI, http.HandlerFunc(aiHandler.GenerateCurriculumHandler)), ""))
	mux.Handle("/api/ai/curriculum", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileAI, http.HandlerFunc(aiHandler.GenerateCurriculumHandler)), ""))

	// Room & Zoom Webhook Initialization
	roomStateManager := room.NewRoomStateManager(redisClient)
	roomHub := ports.NewRoomHub()
	roomHandler := &ports.RoomHandler{DB: dbpool, StateManager: roomStateManager}
	mux.Handle("/api/v1/rooms/create", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileRooms, http.HandlerFunc(roomHandler.CreateRoomHandler)), ""))
	mux.Handle("/api/v1/rooms/active", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileRooms, http.HandlerFunc(roomHandler.ActiveRoomsHandler)), ""))
	mux.Handle("/api/v1/rooms/state/", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileRooms, http.HandlerFunc(roomHandler.RoomStateHandler)), ""))

	zoomWebhookHandler := integration_zoom.NewWebhookHandler(roomStateManager, dbpool)
	mux.HandleFunc("/api/webhooks/zoom", zoomWebhookHandler.HandleZoomWebhook)

	// Websockets (Protected)
	socketConn := &ports.SocketConnection{
		DB:                dbpool,
		StateManager:      roomStateManager,
		Hub:               roomHub,
		ConnectionLimiter: abuse.NewDefaultActiveConnectionLimiter(),
	}
	mux.Handle("/api/v1/rooms/stream/", auth.RBACMiddleware(abuseLimiter.Middleware(abuse.ProfileWebSocket, http.HandlerFunc(socketConn.HandleLiveRoom)), ""))

	return observer.Middleware(&mux)
}

func liveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func readyHandler(dbpool *pgxpool.Pool, redisClient *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
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

	dbpool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer dbpool.Close()

	if err := dbpool.Ping(ctx); err != nil {
		log.Fatalf("Database ping failed: %v", err)
	}
	log.Println("Successfully connected to PostgreSQL pool.")

	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Redis initialization failed: %v", err)
	}

	rdb := redis.NewClient(opt)
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
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

	router := setupRoutes(dbpool, vectorDB, rdb)
	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		log.Printf("Server listening on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	log.Println("Received termination signal. Initiating graceful shutdown...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Shutdown complete.")
}
