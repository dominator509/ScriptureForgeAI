package ports

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

// SocketConnection handles a secure websocket routing block
type SocketConnection struct {
	// Upgrade dependencies will be mapped here
	AllowedOrigins []string
}

func (s *SocketConnection) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Allow empty origins for non-browser clients (e.g., mobile app)
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		return false // Reject invalid origin URLs
	}

	for _, allowed := range s.AllowedOrigins {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}

		allowedURL, err := url.Parse(allowed)
		if err != nil {
			continue // Skip badly formatted allowed origins
		}

		if originURL.Scheme != allowedURL.Scheme {
			continue
		}

		// Support wildcard subdomains e.g. *.scriptureforgeai.com
		if strings.HasPrefix(allowedURL.Host, "*.") {
			baseDomain := strings.TrimPrefix(allowedURL.Host, "*")
			if strings.HasSuffix(originURL.Host, baseDomain) {
				return true
			}
		} else if originURL.Host == allowedURL.Host {
			return true // Exact match
		}
	}

	return false
}

func (s *SocketConnection) HandleLiveRoom(w http.ResponseWriter, r *http.Request) {
	// The request has already passed the RBACMiddleware, which validated the token.
	log.Println("Websocket connection authenticated via Middleware. Upgrading...")

	upgrader := websocket.Upgrader{
		CheckOrigin: s.checkOrigin,
	}

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
