package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	defaultAPIRequestTimeout = 15 * time.Second
	minAPIRequestTimeout     = time.Second
	maxAPIRequestTimeout     = 2 * time.Minute
)

// apiRequestDeadlineMiddleware bounds ordinary API work while leaving upgraded
// room streams to their connection-owned read, write, and ping deadlines.
func apiRequestDeadlineMiddleware(next http.Handler, timeout time.Duration) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || isLongLivedAPIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isLongLivedAPIPath(path string) bool {
	return path == "/api/v1/rooms/stream" || strings.HasPrefix(path, "/api/v1/rooms/stream/")
}
