package ports

import (
	"net/http"
	"testing"
)

func TestSocketConnection_checkOrigin(t *testing.T) {
	s := &SocketConnection{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"https://scriptureforgeai.com",
			"https://*.scriptureforgeai.com",
		},
	}

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{
			name:   "Exact match - localhost",
			origin: "http://localhost:3000",
			want:   true,
		},
		{
			name:   "Exact match - production",
			origin: "https://scriptureforgeai.com",
			want:   true,
		},
		{
			name:   "Wildcard match - valid subdomain",
			origin: "https://app.scriptureforgeai.com",
			want:   true,
		},
		{
			name:   "Wildcard match - valid nested subdomain",
			origin: "https://beta.app.scriptureforgeai.com",
			want:   true,
		},
		{
			name:   "Reject - unknown origin",
			origin: "https://malicious.com",
			want:   false,
		},
		{
			name:   "Reject - mismatched scheme",
			origin: "http://scriptureforgeai.com", // Expected https
			want:   false,
		},
		{
			name:   "Reject - similar domain spoofing",
			origin: "https://myscriptureforgeai.com",
			want:   false,
		},
		{
			name:   "Allow - Empty origin (non-browser client)",
			origin: "",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/ws", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Origin", tt.origin)

			if got := s.checkOrigin(req); got != tt.want {
				t.Errorf("checkOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}
