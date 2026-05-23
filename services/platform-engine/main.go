package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	// In-memory mocks for Postgres and Redis
	studyPlans   sync.Map
	zoomSessions sync.Map
	searchLogs   sync.Map

	redisMock sync.Map

	transactionCount int
	mu               sync.Mutex
	walFile          *os.File
	walMutex         sync.Mutex

	// Rate Limiting & Circuit Breaker
	concurrentRequests int
	maxConcurrent      = 500 // Arbitrary safe limit for mock environment
	reqMutex           sync.Mutex
)

// WalEntry represents a write-ahead log entry
type WalEntry struct {
	ID        int64                  `json:"id"`
	Type      string                 `json:"type"`
	Payload   map[string]interface{} `json:"payload"`
	Timestamp time.Time              `json:"timestamp"`
}

func initWAL() {
	log.Println("Initializing Write-Ahead Log (WAL)...")
	var err error

	if file, err := os.Open("state_wal.log"); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var entry WalEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
				switch entry.Type {
				case "generate":
					studyPlans.Store(entry.ID, entry.Payload)
					redisMock.Store(fmt.Sprintf("plan:%d", entry.ID), "processing")
				case "zoom":
					zoomSessions.Store(entry.ID, entry.Payload)
				case "search":
					searchLogs.Store(entry.ID, entry.Payload)
				}
				mu.Lock()
				transactionCount++
				mu.Unlock()
			}
		}
		file.Close()
		log.Printf("WAL Recovery complete. Recovered %d transactions.\n", transactionCount)
	} else {
		log.Println("No existing WAL found. Starting fresh.")
	}

	walFile, err = os.OpenFile("state_wal.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open WAL file: %v", err)
	}
}

func appendWAL(entryType string, id int64, payload map[string]interface{}) {
	entry := WalEntry{
		ID:        id,
		Type:      entryType,
		Payload:   payload,
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal WAL entry: %v", err)
		return
	}

	walMutex.Lock()
	defer walMutex.Unlock()

	if _, err := walFile.Write(append(data, '\n')); err != nil {
		log.Printf("Failed to write to WAL: %v", err)
		return
	}
	walFile.Sync()
}

// circuitBreakerMiddleware limits the number of concurrent requests.
// If the server is overloaded, it returns a 503 Service Unavailable immediately.
func circuitBreakerMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqMutex.Lock()
		if concurrentRequests >= maxConcurrent {
			reqMutex.Unlock()
			http.Error(w, `{"error": "Service Unavailable - Circuit Breaker Tripped"}`, http.StatusServiceUnavailable)
			return
		}
		concurrentRequests++
		reqMutex.Unlock()

		defer func() {
			reqMutex.Lock()
			concurrentRequests--
			reqMutex.Unlock()
		}()

		next.ServeHTTP(w, r)
	}
}

func main() {
	initAuthSystem()
	http.HandleFunc("/api/v1/auth/login", circuitBreakerMiddleware(handleLogin))
	http.HandleFunc("/api/v1/auth/register", circuitBreakerMiddleware(handleRegister))
	initWAL()
	log.Println("Starting mock platform-engine (in-memory db with WAL and Circuit Breaker)...")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/ai/generate", circuitBreakerMiddleware(handleGenerate))
	http.HandleFunc("/api/zoom/active", circuitBreakerMiddleware(handleZoom))
	http.HandleFunc("/api/search", circuitBreakerMiddleware(handleSearch))
	http.HandleFunc("/api/state", handleStateHash)

	server := &http.Server{Addr: ":8080"}

	go func() {
		log.Println("Listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	if walFile != nil {
		walFile.Close()
	}

	log.Println("Server exiting")
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	time.Sleep(50 * time.Millisecond)

	id := time.Now().UnixNano()

	payload := map[string]interface{}{
		"title":   fmt.Sprintf("Plan %d", id),
		"content": "Generated content...",
		"time":    time.Now().Format(time.RFC3339Nano),
	}

	appendWAL("generate", id, payload)

	studyPlans.Store(id, payload)
	redisMock.Store(fmt.Sprintf("plan:%d", id), "processing")

	mu.Lock()
	transactionCount++
	mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "generated", "id": id})
}

func handleZoom(w http.ResponseWriter, r *http.Request) {
	id := time.Now().UnixNano()

	payload := map[string]interface{}{
		"meeting_id":   fmt.Sprintf("zoom-%d", id),
		"participants": 10,
		"status":       "active",
		"time":         time.Now().Format(time.RFC3339Nano),
	}

	appendWAL("zoom", id, payload)

	zoomSessions.Store(id, payload)

	mu.Lock()
	transactionCount++
	mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "active", "id": id})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	time.Sleep(20 * time.Millisecond)
	id := time.Now().UnixNano()

	payload := map[string]interface{}{
		"query":         "grace",
		"results_count": 10000,
		"time":          time.Now().Format(time.RFC3339Nano),
	}

	appendWAL("search", id, payload)

	searchLogs.Store(id, payload)

	mu.Lock()
	transactionCount++
	mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "searched", "hits": 10000})
}

func handleStateHash(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	count := transactionCount
	mu.Unlock()

	hash := fmt.Sprintf("HASH_TX_%d", count)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"hash":         hash,
		"transactions": count,
	})
}
