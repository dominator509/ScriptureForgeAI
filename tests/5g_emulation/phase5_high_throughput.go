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

// Simulates highly concurrent data sync endpoints
func mockEdgeSyncEndpoint(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}
		// Simulate state diff application and sync broadcast
		_ = c.WriteMessage(mt, message)
	}
}

func main() {
	fmt.Println("Phase 5: High-Throughput Edge Synchronization (Theoretical limits under URLLC/Jitter)")

	server := httptest.NewServer(http.HandlerFunc(mockEdgeSyncEndpoint))
	defer server.Close()

	fw, err := NewEmulationFramework("sync_test", "localhost:8478", server.Listener.Addr().String())
	if err != nil {
		log.Fatalf("Failed to initialize framework: %v", err)
	}
	defer fw.Proxy.Delete()

	fw.Reset()

	// Apply both URLLC latency and RAN jitter constraints to the sync pipeline
	fw.ApplyURLLC()
	fw.ApplyRANJitter()

	wsURL := "ws://localhost:8478"

	var wg sync.WaitGroup
	numWorkers := 200     // 200 concurrent sync streams
	payloadsPerWorker := 1000 // Each sending 1000 state mutations

	var totalProcessed uint64
	var dropped uint64

	fmt.Printf("Starting %d Edge nodes, syncing %d mutations each over throttled link...\n", numWorkers, payloadsPerWorker)

	startTest := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				atomic.AddUint64(&dropped, uint64(payloadsPerWorker))
				return
			}
			defer c.Close()

			payload := generateRandomPayload(128) // 128 bytes per mutation diff

			for j := 0; j < payloadsPerWorker; j++ {
				err := c.WriteMessage(websocket.BinaryMessage, payload)
				if err != nil {
					atomic.AddUint64(&dropped, 1)
					continue
				}

				_, _, err = c.ReadMessage()
				if err != nil {
					atomic.AddUint64(&dropped, 1)
					continue
				}

				atomic.AddUint64(&totalProcessed, 1)
			}
		}(i)
	}

	wg.Wait()
	testDuration := time.Since(startTest)
	tps := float64(totalProcessed) / testDuration.Seconds()

	fmt.Printf("Total Processed: %d / %d mutations\n", totalProcessed, numWorkers*payloadsPerWorker)
	fmt.Printf("Dropped Mutations: %d\n", dropped)
	fmt.Printf("Test Duration: %s\n", testDuration)
	fmt.Printf("Throughput under 5G Jitter Constraints: %.2f TPS\n", tps)

	violationMsg := ""
	if float64(dropped)/float64(numWorkers*payloadsPerWorker) > 0.05 { // >5% drop rate
		violationMsg = "HIGH THROUGHPUT ASSERTION FAILED: Excessive mutation drops under heavy load and jitter. Data consistency fractured."
		fmt.Println(violationMsg)
	} else if tps < 1000 {
		violationMsg = fmt.Sprintf("HIGH THROUGHPUT WARNING: Sync pipeline is severely bottlenecked (%.2f TPS). Fails to meet high-speed edge requirements.", tps)
		fmt.Println(violationMsg)
	} else {
		fmt.Println("HIGH THROUGHPUT ASSERTION PASSED: System scaled and maintained data synchronization under severe 5G emulation.")
	}

	f, _ := os.OpenFile("phase5_report.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	defer f.Close()
	fmt.Fprintf(f, "Phase 5: High-Throughput Sync\nWorkers: %d\nTotal Processed: %d\nDrops: %d\nThroughput: %.2f TPS\n%s\n", numWorkers, totalProcessed, dropped, tps, violationMsg)
}
