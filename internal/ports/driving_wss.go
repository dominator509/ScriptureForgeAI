package ports

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

// SocketConnection handles a secure websocket routing block
type SocketConnection struct {
	// Upgrade dependencies will be mapped here
}

func getUpgrader() websocket.Upgrader {
	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		allowedOrigins = "http://localhost:3000" // Default for local development
	}
	origins := strings.Split(allowedOrigins, ",")

	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// If it's a direct programmatic client without origin, it might be allowed,
				// but generally browsers send Origin. We enforce it strictly.
				return false
			}

			for _, allowed := range origins {
				if origin == strings.TrimSpace(allowed) {
					return true
				}
			}
			log.Printf("WebSocket connection rejected for insecure origin: %s", origin)
			return false
		},
	}
}

func (s *SocketConnection) HandleLiveRoom(w http.ResponseWriter, r *http.Request) {
	// The request has already passed the RBACMiddleware, which validated the token.
	log.Println("Websocket connection authenticated via Middleware. Upgrading...")

	upgrader := getUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	defer conn.Close()

	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("read error:", err)
			break
		}
		log.Printf("recv: %s", message)
		err = conn.WriteMessage(mt, message)
		if err != nil {
			log.Println("write error:", err)
			break
		}
	}
}
