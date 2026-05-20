package ports

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // In production this must be scoped to the actual origins
	},
}

// SocketConnection handles a secure websocket routing block
type SocketConnection struct {
	// Upgrade dependencies will be mapped here
}

func (s *SocketConnection) HandleLiveRoom(w http.ResponseWriter, r *http.Request) {
	// The request has already passed the RBACMiddleware, which validated the token.
	log.Println("Websocket connection authenticated via Middleware. Upgrading...")

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
