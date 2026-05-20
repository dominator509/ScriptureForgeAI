package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

// mockStreamingEndpoint simulates the driving_wss.go websocket endpoint
func mockStreamingEndpoint(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}
		// Echo back to simulate state sync
		err = c.WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}

func main() {
	fmt.Println("Phase 3: 5G RAN Jitter & Asynchronous Arrival Testing")

	server := httptest.NewServer(http.HandlerFunc(mockStreamingEndpoint))
	defer server.Close()

	fw, err := NewEmulationFramework("ran_jitter_test", "localhost:8476", server.Listener.Addr().String())
	if err != nil {
		log.Fatalf("Failed to initialize framework: %v", err)
	}
	defer fw.Proxy.Delete()

	fw.Reset()

	// Emulate micro-bursts and heavy out-of-order packets
	err = fw.ApplyRANJitter()
	if err != nil {
		log.Fatalf("Failed to apply RAN Jitter: %v", err)
	}

	wsURL := "ws://localhost:8476"

	var wg sync.WaitGroup
	numConnections := 100
	wg.Add(numConnections)

	var panics uint32
	var drops uint32
	var seqErrors uint32

	fmt.Printf("Opening %d stateful websocket connections through high-jitter RAN emulator...\n", numConnections)

	startTest := time.Now()

	for i := 0; i < numConnections; i++ {
		go func(connID int) {
			defer wg.Done()

			// Handle any application panics
			defer func() {
				if r := recover(); r != nil {
					atomic.AddUint32(&panics, 1)
				}
			}()

			c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				atomic.AddUint32(&drops, 1)
				return
			}
			defer c.Close()

			// Send rapid burst of packets
			burstSize := 50
			for j := 0; j < burstSize; j++ {
				payload := []byte(fmt.Sprintf("seq_%d_%d", connID, j))
				err := c.WriteMessage(websocket.TextMessage, payload)
				if err != nil {
					atomic.AddUint32(&drops, 1)
					return
				}

				_, message, err := c.ReadMessage()
				if err != nil {
					atomic.AddUint32(&drops, 1)
					return
				}

				// Verify sequence (if they arrive completely garbled or out of order due to buffer overflow)
				// In a real state machine, we'd check if the backend applied state correctly.
				// For this test, if we get back something different than what we sent immediately (echo),
				// it means the pipeline is garbling state under jitter.
				if string(message) != string(payload) {
					atomic.AddUint32(&seqErrors, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	testDuration := time.Since(startTest)

	fmt.Printf("Test Duration: %s\n", testDuration)
	fmt.Printf("Connection Drops: %d\n", drops)
	fmt.Printf("Sequence/Buffer Errors: %d\n", seqErrors)
	fmt.Printf("Application Panics: %d\n", panics)

	violationMsg := ""
	if panics > 0 || seqErrors > 0 {
		violationMsg = fmt.Sprintf("RAN JITTER ASSERTION FAILED: System buffers overflowed or panicked under micro-bursts. Panics: %d, Sequence Errors: %d", panics, seqErrors)
		fmt.Println(violationMsg)
	} else if drops > 50 {
		violationMsg = fmt.Sprintf("RAN JITTER WARNING: High connection drop rate (%d) under jitter, may need better retry/backoff buffers.", drops)
		fmt.Println(violationMsg)
	} else {
		fmt.Println("RAN JITTER ASSERTION PASSED: Stateful endpoints maintained stability under heavy jitter and micro-bursts.")
	}

	f, _ := os.OpenFile("phase3_report.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	defer f.Close()
	fmt.Fprintf(f, "Phase 3: RAN Jitter Testing\nConnections: %d\nDrops: %d\nSequence Errors: %d\nPanics: %d\n%s\n", numConnections, drops, seqErrors, panics, violationMsg)
}
