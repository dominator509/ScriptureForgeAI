package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultAPIRequestTimeout = 15 * time.Second
	minAPIRequestTimeout     = time.Second
	maxAPIRequestTimeout     = 2 * time.Minute
	defaultShutdownTimeout   = 10 * time.Second
	minShutdownTimeout       = time.Second
	maxShutdownTimeout       = 2 * time.Minute
)

type serverLifecycle struct {
	draining     atomic.Bool
	shutdownOnce sync.Once
	onShutdown   func()
}

func (s *serverLifecycle) beginShutdown() {
	if s == nil {
		return
	}
	s.shutdownOnce.Do(func() {
		s.draining.Store(true)
		if s.onShutdown != nil {
			s.onShutdown()
		}
	})
}

func (s *serverLifecycle) isDraining() bool {
	return s != nil && s.draining.Load()
}

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
