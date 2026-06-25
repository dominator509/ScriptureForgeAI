package abuse

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"scriptureforge/internal/domain/auth"
)

const (
	ProfileAuth      = "auth"
	ProfileAI        = "ai"
	ProfileJournal   = "journal"
	ProfileRooms     = "rooms"
	ProfileWebSocket = "websocket"
)

type Profile struct {
	Name   string
	Limit  int
	Window time.Duration
}

type Policy struct {
	Profiles map[string]Profile
}

type Limiter struct {
	mu      sync.Mutex
	policy  Policy
	buckets map[string]bucket
	now     func() time.Time
}

type bucket struct {
	count     int
	windowEnd time.Time
}

type rateLimitError struct {
	Category string `json:"category"`
	Message  string `json:"message"`
	Code     int    `json:"code"`
}

func PolicyFromEnv() Policy {
	return Policy{Profiles: map[string]Profile{
		ProfileAuth:      profileFromEnv(ProfileAuth, 10, time.Minute),
		ProfileAI:        profileFromEnv(ProfileAI, 20, time.Minute),
		ProfileJournal:   profileFromEnv(ProfileJournal, 120, time.Minute),
		ProfileRooms:     profileFromEnv(ProfileRooms, 120, time.Minute),
		ProfileWebSocket: profileFromEnv(ProfileWebSocket, 30, time.Minute),
	}}
}

func profileFromEnv(name string, defaultLimit int, defaultWindow time.Duration) Profile {
	envPrefix := "ABUSE_LIMIT_" + strings.ToUpper(name)
	limit := intFromEnv(envPrefix+"_REQUESTS", defaultLimit)
	windowSeconds := intFromEnv(envPrefix+"_WINDOW_SECONDS", int(defaultWindow.Seconds()))
	if limit < 1 {
		limit = defaultLimit
	}
	if windowSeconds < 1 {
		windowSeconds = int(defaultWindow.Seconds())
	}
	return Profile{Name: name, Limit: limit, Window: time.Duration(windowSeconds) * time.Second}
}

func intFromEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func NewLimiter(policy Policy) *Limiter {
	return &Limiter{
		policy:  policy,
		buckets: map[string]bucket{},
		now:     time.Now,
	}
}

func NewDefaultLimiter() *Limiter {
	return NewLimiter(PolicyFromEnv())
}

func (l *Limiter) Middleware(profileName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profile, ok := l.policy.Profiles[profileName]
		if !ok || profile.Limit < 1 || profile.Window <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		allowed, retryAfter := l.allow(profile, identityForRequest(r, profileName))
		if !allowed {
			writeRateLimitError(w, profile, retryAfter)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) allow(profile Profile, identity string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	key := profile.Name + ":" + identity
	current := l.buckets[key]
	if current.windowEnd.IsZero() || !now.Before(current.windowEnd) {
		l.buckets[key] = bucket{count: 1, windowEnd: now.Add(profile.Window)}
		return true, 0
	}
	if current.count >= profile.Limit {
		return false, time.Until(current.windowEnd)
	}
	current.count++
	l.buckets[key] = current
	return true, 0
}

func identityForRequest(r *http.Request, profileName string) string {
	if claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims); ok && claims != nil {
		return "tenant:" + claims.OrganizationID + ":user:" + claims.UserID + ":profile:" + profileName
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return "ip:" + host + ":profile:" + profileName
	}
	if r.RemoteAddr != "" {
		return "remote:" + r.RemoteAddr + ":profile:" + profileName
	}
	return "unknown:profile:" + profileName
}

func writeRateLimitError(w http.ResponseWriter, profile Profile, retryAfter time.Duration) {
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second).Seconds())))
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(profile.Limit))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(rateLimitError{
		Category: "ABUSE_RATE_LIMIT_FAULT",
		Message:  "rate limit exceeded for " + profile.Name,
		Code:     http.StatusTooManyRequests,
	})
}
