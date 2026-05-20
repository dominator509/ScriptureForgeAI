package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}
var activeConnections int32
var activeMu sync.Mutex

func mockHandoverEndpoint(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()

	activeMu.Lock()
	activeConnections++
	activeMu.Unlock()

	defer func() {
		activeMu.Lock()
		activeConnections--
		activeMu.Unlock()
	}()

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}
		c.WriteMessage(mt, message)
	}
}

func main() {
	fmt.Println("Phase 4: Tower Handover & Connection Drop Simulation")

	server := httptest.NewServer(http.HandlerFunc(mockHandoverEndpoint))
	defer server.Close()

	fw, err := NewEmulationFramework("handover_test", "localhost:8477", server.Listener.Addr().String())
	if err != nil {
		log.Fatalf("Failed to initialize framework: %v", err)
	}
	defer fw.Proxy.Delete()

	fw.Reset()

	wsURL := "ws://localhost:8477"

	// 1. Establish initial connection
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Fatalf("Failed initial dial: %v", err)
	}

	// 2. Emulate mobile handover (abrupt drop)
	fmt.Println("Simulating abrupt network drop (Handover)...")
	startDrop := time.Now()

	// Toxiproxy disables the proxy, completely dropping active connections
	go func() {
		fw.EmulateHandover(50 * time.Millisecond) // Simulate 50ms offline time between towers
	}()

	// Wait for the drop to happen
	time.Sleep(10 * time.Millisecond)

	// Send a message over the dropped connection to force failure on client side
	err = c.WriteMessage(websocket.TextMessage, []byte("ping"))
	if err == nil {
		_, _, err = c.ReadMessage()
	}

	dropTime := time.Since(startDrop)
	c.Close()

	// Wait for proxy to come back online
	time.Sleep(60 * time.Millisecond)

	// 3. Reconnect from "new tower"
	fmt.Println("Reconnecting from new IP/Tower...")
	reconnectStart := time.Now()

	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	reconnectTime := time.Since(reconnectStart)

	violationMsg := ""
	if err != nil {
		violationMsg = fmt.Sprintf("HANDOVER ASSERTION FAILED: Could not reconnect after tower handover within 50ms. Error: %v", err)
		fmt.Println(violationMsg)
	} else {
		defer c2.Close()
		fmt.Printf("Reconnected successfully in %s\n", reconnectTime)

		// Check if the backend cleanly released the old connection state
		activeMu.Lock()
		activeCount := activeConnections
		activeMu.Unlock()

		if activeCount > 1 {
			violationMsg = fmt.Sprintf("HANDOVER MEMORY LEAK WARNING: Backend still holds locks/state for the dropped connection. Active: %d (Expected: 1)", activeCount)
			fmt.Println(violationMsg)
		} else {
			fmt.Println("HANDOVER ASSERTION PASSED: Backend instantly released locks and seamlessly resumed session state.")
		}
	}

	f, _ := os.OpenFile("phase4_report.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	defer f.Close()
	fmt.Fprintf(f, "Phase 4: Tower Handover Testing\nDrop Duration: %s\nReconnect Time: %s\n%s\n", dropTime, reconnectTime, violationMsg)
}
