package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"scriptureforge/internal/adapters/integration_zoom"
	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/room"
	"scriptureforge/internal/ports"
)

type ErrorCategory string

const (
	AIOrchestrationEngineFault ErrorCategory = "AI_ORCHESTRATION_ENGINE_FAULT"
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
	DatabaseURL string
	RedisURL    string
	Port        string
	GRPCAddress string
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
		grpcAddr = "localhost:50051"
	}

	return &Config{
		DatabaseURL: dbURL,
		RedisURL:    redisURL,
		Port:        port,
		GRPCAddress: grpcAddr,
	}, nil
}

func setupRoutes(dbpool *pgxpool.Pool, vectorDB ai.VectorDB, redisClient *redis.Client) *http.ServeMux {
	mux := http.ServeMux{}

	// Auth Endpoints
	authHandler := &ports.AuthHandler{DB: dbpool}
	mux.HandleFunc("/api/auth/register", authHandler.RegisterHandler)
	mux.HandleFunc("/api/auth/login", authHandler.LoginHandler)

	// AI Endpoints (Protected by RBAC)
	ragEngine := ai.NewRAGEngine(vectorDB)
	mapReduceWorker := ai.NewMapReduceWorker(4000)

	aiHandler := &ports.AIHandler{
		RAGEngine:       ragEngine,
		Verifier:        ai.NewResponseVerificationSubsystem(),
		LLMClient:       llm.NewLLMClient(),
		MapReduceWorker: mapReduceWorker,
	}
	mux.Handle("/api/ai/curriculum", auth.RBACMiddleware(http.HandlerFunc(aiHandler.GenerateCurriculumHandler), ""))

	// Room & Zoom Webhook Initialization
	roomStateManager := room.NewRoomStateManager(redisClient)
	zoomWebhookHandler := integration_zoom.NewWebhookHandler(roomStateManager)
	mux.HandleFunc("/api/webhooks/zoom", zoomWebhookHandler.HandleZoomWebhook)

	// Websockets (Protected)
	socketConn := &ports.SocketConnection{}
	mux.Handle("/ws/room", auth.RBACMiddleware(http.HandlerFunc(socketConn.HandleLiveRoom), ""))

	return &mux
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, errConfig := loadConfig()
	if errConfig != nil {
		log.Fatalf("Initialization failed: %v", errConfig)
	}

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

	vectorClient, err := ai.NewGRPCScriptureClient(cfg.GRPCAddress)
	if err != nil {
		log.Printf("Warning: Failed to connect to Rust gRPC Scripture Engine at %s: %v. AI features will fail.", cfg.GRPCAddress, err)
	} else {
		defer vectorClient.Close()
		log.Println("Successfully connected to Rust gRPC Scripture Engine.")
	}

	router := setupRoutes(dbpool, vectorClient, rdb)
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
