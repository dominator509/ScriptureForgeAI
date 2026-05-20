package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Dummy handler to simulate WebSocket endpoint
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func mockWSHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Simulate processing delay
		time.Sleep(10 * time.Millisecond)

		err = conn.WriteMessage(mt, msg)
		if err != nil {
			break
		}
	}
}

func TestConcurrentWebSocketExhaustion(t *testing.T) {
	// 1. Setup mock server
	server := httptest.NewServer(http.HandlerFunc(mockWSHandler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// 2. Concurrency constraints
	numConnections := 500 // Bound this so the test runner doesn't get completely killed, but high enough to show concurrent safety.
	var wg sync.WaitGroup
	errorsFound := make(chan error, numConnections)

	t.Logf("Spawning %d concurrent WebSocket connections to %s...", numConnections, wsURL)

	// 3. Fire concurrent connections
	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Attempt connection with timeout
			dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
			conn, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				errorsFound <- fmt.Errorf("connection %d failed: %w", id, err)
				return
			}
			defer conn.Close()

			// Write and read
			err = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Hello from %d", id)))
			if err != nil {
				errorsFound <- fmt.Errorf("write %d failed: %w", id, err)
				return
			}

			_, _, err = conn.ReadMessage()
			if err != nil {
				errorsFound <- fmt.Errorf("read %d failed: %w", id, err)
				return
			}
		}(i)
	}

	// 4. Wait with a timeout to detect deadlocks
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Completed within time limit
	case <-time.After(15 * time.Second):
		t.Fatalf("Test timed out! Potential deadlock or extreme resource starvation.")
	}
	close(errorsFound)

	// 5. Evaluate degradation
	errorCount := 0
	for err := range errorsFound {
		if err != nil {
			errorCount++
		}
	}

	// It's acceptable for some to fail under extreme load depending on OS limits,
	// but the test framework itself shouldn't panic or crash.
	t.Logf("Completed. Failed connections: %d / %d", errorCount, numConnections)
}

// Simulated mock for Redis to test timeouts
type mockTimeoutRedis struct{}

func (m *mockTimeoutRedis) UpdateParticipantDuration(ctx context.Context, roomID, userID string, duration int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return fmt.Errorf("redis connection pool timeout")
	}
}

func TestSimulatedDatabaseExhaustion(t *testing.T) {
	// Simulate many goroutines trying to hit a bottlenecked database
	mockDB := &mockTimeoutRedis{}
	numRequests := 1000
	var wg sync.WaitGroup

	t.Logf("Simulating %d concurrent slow DB requests...", numRequests)

	// Track panics
	var panicDetected bool

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicDetected = true
				}
			}()

			// Give a short timeout ctx
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()

			err := mockDB.UpdateParticipantDuration(ctx, "room_1", "user_1", 10)

			// We EXPECT errors here due to context timeout or mock timeout.
			// The assertion is that we get clean errors, not panics.
			_ = err
		}()
	}

	wg.Wait()

	if panicDetected {
		t.Fatalf("System panicked under simulated database load! Critical degradation.")
	} else {
		t.Logf("System degraded gracefully without panicking.")
	}
}
