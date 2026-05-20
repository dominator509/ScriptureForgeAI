package main

import (
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
	studyPlans  sync.Map
	zoomSessions sync.Map
	searchLogs   sync.Map

	redisMock   sync.Map

	transactionCount int
	mu               sync.Mutex
)

func main() {
	log.Println("Starting mock platform-engine (in-memory db)...")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/ai/generate", handleGenerate)
	http.HandleFunc("/api/zoom/active", handleZoom)
	http.HandleFunc("/api/search", handleSearch)
	http.HandleFunc("/api/state", handleStateHash)

	server := &http.Server{Addr: ":8080"}

	go func() {
		log.Println("Listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	// We want to test hard kills, but we'll add standard handlers just in case
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
	log.Println("Server exiting")
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	// Simulate heavy AI task
	time.Sleep(50 * time.Millisecond)

	id := time.Now().UnixNano()

	studyPlans.Store(id, map[string]interface{}{
		"title":   fmt.Sprintf("Plan %d", id),
		"content": "Generated content...",
		"time":    time.Now(),
	})

	redisMock.Store(fmt.Sprintf("plan:%d", id), "processing")

	mu.Lock()
	transactionCount++
	mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "generated", "id": id})
}

func handleZoom(w http.ResponseWriter, r *http.Request) {
	// Simulate active zoom session updates
	id := time.Now().UnixNano()

	zoomSessions.Store(id, map[string]interface{}{
		"meeting_id":   fmt.Sprintf("zoom-%d", id),
		"participants": 10,
		"status":       "active",
		"time":         time.Now(),
	})

	mu.Lock()
	transactionCount++
	mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "active", "id": id})
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	// Simulate deep search
	time.Sleep(20 * time.Millisecond)
	id := time.Now().UnixNano()

	searchLogs.Store(id, map[string]interface{}{
		"query":         "grace",
		"results_count": 10000,
		"time":          time.Now(),
	})

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
		"hash": hash,
		"transactions": count,
	})
}
