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
	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/ports"
)

// ... (PlatformException and Config structs omitted for brevity in this replace, assume they exist as before) ...

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
	DatabaseURL string
	RedisURL    string
	Port        string
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

	return &Config{
		DatabaseURL: dbURL,
		RedisURL:    redisURL,
		Port:        port,
	}, nil
}

func setupRoutes() *http.ServeMux {
	mux := http.ServeMux{}

	// Zoom Webhook
	mux.HandleFunc("/api/webhooks/zoom", integration_zoom.HandleZoomWebhook)

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

	router := setupRoutes()
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
