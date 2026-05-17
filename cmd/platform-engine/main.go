package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// ErrorCategory defines the taxonomy of errors in the system.
type ErrorCategory string

const (
	AIOrchestrationEngineFault ErrorCategory = "AI_ORCHESTRATION_ENGINE_FAULT"
	DatabaseConnectionFault    ErrorCategory = "DATABASE_CONNECTION_FAULT"
	CacheConnectionFault       ErrorCategory = "CACHE_CONNECTION_FAULT"
	ConfigurationFault         ErrorCategory = "CONFIGURATION_FAULT"
)

// PlatformException represents a strongly-typed system error.
type PlatformException struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Code     int           `json:"code"`
	TraceID  string        `json:"trace_id"`
}

func (e *PlatformException) Error() string {
	return fmt.Sprintf("[%s] %s (Trace: %s)", e.Category, e.Message, e.TraceID)
}

// Config holds environment variables.
type Config struct {
	DatabaseURL string
	RedisURL    string
}

// loadConfig parses environment variables.
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

	return &Config{
		DatabaseURL: dbURL,
		RedisURL:    redisURL,
	}, nil
}

func main() {
	// Initialize context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load Configuration
	cfg, errConfig := loadConfig()
	if errConfig != nil {
		log.Fatalf("Initialization failed: %v", errConfig)
	}

	// Initialize PostgreSQL Connection Pool
	dbpool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		pgErr := &PlatformException{
			Category: DatabaseConnectionFault,
			Message:  fmt.Sprintf("Unable to create connection pool: %v", err),
			Code:     500,
		}
		log.Fatalf("Database initialization failed: %v", pgErr)
	}
	defer dbpool.Close()

	if err := dbpool.Ping(ctx); err != nil {
		pgErr := &PlatformException{
			Category: DatabaseConnectionFault,
			Message:  fmt.Sprintf("Unable to ping database: %v", err),
			Code:     500,
		}
		log.Fatalf("Database ping failed: %v", pgErr)
	}
	log.Println("Successfully connected to PostgreSQL pool.")

	// Initialize Redis Connection Pool
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		redisErr := &PlatformException{
			Category: ConfigurationFault,
			Message:  fmt.Sprintf("Unable to parse Redis URL: %v", err),
			Code:     500,
		}
		log.Fatalf("Redis initialization failed: %v", redisErr)
	}

	rdb := redis.NewClient(opt)
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		redisErr := &PlatformException{
			Category: CacheConnectionFault,
			Message:  fmt.Sprintf("Unable to ping Redis: %v", err),
			Code:     500,
		}
		log.Fatalf("Redis ping failed: %v", redisErr)
	}
	log.Println("Successfully connected to Redis pool.")

	// Setup OS signal handling for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	log.Println("ScriptureForge AI Platform Engine started. Waiting for termination signal...")
	<-quit
	log.Println("Received termination signal. Initiating graceful shutdown...")

	// Graceful shutdown with timeout
	_, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Cleanup will happen via defers
	log.Println("Shutdown complete.")
}
