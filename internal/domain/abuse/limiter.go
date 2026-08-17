package abuse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/observability"
)

const (
	ProfileAuth        = "auth"
	ProfileAuthAccount = "auth_account"
	ProfileAI          = "ai"
	ProfileJournal     = "journal"
	ProfileRooms       = "rooms"
	ProfileWebSocket   = "websocket"
)

type Profile struct {
	Name   string
	Limit  int
	Window time.Duration
}

type Policy struct {
	Profiles   map[string]Profile
	MaxBuckets int
}

type Limiter struct {
	mu         sync.Mutex
	policy     Policy
	buckets    map[string]bucket
	now        func() time.Time
	maxBuckets int
	redis      *redis.Client
}

type ActiveConnectionLimiter struct {
	mu             sync.Mutex
	perUserLimit   int
	perTenantLimit int
	globalLimit    int
	globalCount    int
	users          map[string]int
	tenants        map[string]int
	redis          *redis.Client
	leaseTTL       time.Duration
}

type bucket struct {
	count     int
	windowEnd time.Time
}

type decision struct {
	allowed    bool
	retryAfter time.Duration
	remaining  int
	resetAt    time.Time
}

type Result struct {
	Allowed    bool
	Limit      int
	RetryAfter time.Duration
	Remaining  int
	ResetAt    time.Time
}

type rateLimitError struct {
	Category string `json:"category"`
	Message  string `json:"message"`
	Code     int    `json:"code"`
}

var ErrLimiterBackendUnavailable = errors.New("abuse limiter backend unavailable")
var ErrActiveConnectionBackendUnavailable = errors.New("active connection limiter backend unavailable")
var ErrActiveConnectionLeaseExpired = errors.New("active connection lease expired")

var redisFixedWindowScript = redis.NewScript(`
local bucket_key = KEYS[1]
local registry_key = KEYS[2]
local overflow_key = KEYS[3]
local max_buckets = tonumber(ARGV[2])

if redis.call('SISMEMBER', registry_key, bucket_key) == 0 then
  if redis.call('SCARD', registry_key) >= max_buckets then
    bucket_key = overflow_key
  else
    redis.call('SADD', registry_key, bucket_key)
  end
end

local count = redis.call('INCR', bucket_key)
if redis.call('PTTL', bucket_key) < 0 then
  redis.call('PEXPIRE', bucket_key, ARGV[1])
end
if redis.call('PTTL', registry_key) < 0 then
  redis.call('PEXPIRE', registry_key, ARGV[1])
end
return count
`)

var redisActiveConnectionAcquireScript = redis.NewScript(`
local token = ARGV[1]
local lease_seconds = tonumber(ARGV[2])
local lease_millis = lease_seconds * 1000
local user_limit = tonumber(ARGV[3])
local tenant_limit = tonumber(ARGV[4])
local global_limit = tonumber(ARGV[5])
local now_parts = redis.call('TIME')
local now_millis = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local expires_at = now_millis + lease_millis

for _, key in ipairs(KEYS) do
  redis.call('ZREMRANGEBYSCORE', key, '-inf', now_millis)
end

if redis.call('ZCARD', KEYS[1]) >= global_limit or
   redis.call('ZCARD', KEYS[2]) >= tenant_limit or
   redis.call('ZCARD', KEYS[3]) >= user_limit then
  return 0
end

for _, key in ipairs(KEYS) do
  redis.call('ZADD', key, expires_at, token)
  redis.call('EXPIRE', key, lease_seconds * 2)
end
return 1
`)

var redisActiveConnectionRenewScript = redis.NewScript(`
local token = ARGV[1]
local lease_seconds = tonumber(ARGV[2])
local lease_millis = lease_seconds * 1000
local now_parts = redis.call('TIME')
local now_millis = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local expires_at = now_millis + lease_millis

for _, key in ipairs(KEYS) do
  local current_expiry = redis.call('ZSCORE', key, token)
  if not current_expiry or tonumber(current_expiry) <= now_millis then
    return 0
  end
end

for _, key in ipairs(KEYS) do
  redis.call('ZADD', key, expires_at, token)
  redis.call('EXPIRE', key, lease_seconds * 2)
end
return 1
`)

var redisActiveConnectionReleaseScript = redis.NewScript(`
local token = ARGV[1]
for _, key in ipairs(KEYS) do
  redis.call('ZREM', key, token)
end
return 1
`)

const (
	activeConnectionLeaseTTL       = 2 * time.Minute
	activeConnectionCommandTimeout = 5 * time.Second
)

func PolicyFromEnv() Policy {
	return Policy{Profiles: map[string]Profile{
		ProfileAuth:        profileFromEnv(ProfileAuth, 10, time.Minute),
		ProfileAuthAccount: profileFromEnv(ProfileAuthAccount, 5, time.Minute),
		ProfileAI:          profileFromEnv(ProfileAI, 20, time.Minute),
		ProfileJournal:     profileFromEnv(ProfileJournal, 120, time.Minute),
		ProfileRooms:       profileFromEnv(ProfileRooms, 120, time.Minute),
		ProfileWebSocket:   profileFromEnv(ProfileWebSocket, 30, time.Minute),
	}, MaxBuckets: intFromEnv("ABUSE_LIMIT_MAX_BUCKETS", 100000)}
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
	maxBuckets := policy.MaxBuckets
	if maxBuckets < 1 {
		maxBuckets = 100000
	}
	return &Limiter{
		policy:     policy,
		buckets:    map[string]bucket{},
		now:        time.Now,
		maxBuckets: maxBuckets,
	}
}

func NewRedisLimiter(policy Policy, client *redis.Client) *Limiter {
	limiter := NewLimiter(policy)
	limiter.redis = client
	return limiter
}

func NewDefaultLimiter() *Limiter {
	return NewLimiter(PolicyFromEnv())
}

func NewDefaultRedisLimiter(client *redis.Client) *Limiter {
	return NewRedisLimiter(PolicyFromEnv(), client)
}

func NewActiveConnectionLimiter(perUserLimit, perTenantLimit, globalLimit int) *ActiveConnectionLimiter {
	if perUserLimit < 1 {
		perUserLimit = 4
	}
	if perTenantLimit < 1 {
		perTenantLimit = 100
	}
	if globalLimit < 1 {
		globalLimit = 1000
	}
	return &ActiveConnectionLimiter{
		perUserLimit:   perUserLimit,
		perTenantLimit: perTenantLimit,
		globalLimit:    globalLimit,
		users:          map[string]int{},
		tenants:        map[string]int{},
		leaseTTL:       activeConnectionLeaseTTL,
	}
}

func NewDefaultActiveConnectionLimiter() *ActiveConnectionLimiter {
	return NewActiveConnectionLimiterFromClient(nil)
}

func NewRedisActiveConnectionLimiter(perUserLimit, perTenantLimit, globalLimit int, client *redis.Client) *ActiveConnectionLimiter {
	limiter := NewActiveConnectionLimiter(perUserLimit, perTenantLimit, globalLimit)
	limiter.redis = client
	return limiter
}

func NewDefaultRedisActiveConnectionLimiter(client *redis.Client) *ActiveConnectionLimiter {
	return NewRedisActiveConnectionLimiterFromClient(client)
}

func NewActiveConnectionLimiterFromClient(client *redis.Client) *ActiveConnectionLimiter {
	limiter := NewActiveConnectionLimiter(
		intFromEnv("WS_MAX_ACTIVE_CONNECTIONS_PER_USER", 4),
		intFromEnv("WS_MAX_ACTIVE_CONNECTIONS_PER_TENANT", 100),
		intFromEnv("WS_MAX_ACTIVE_CONNECTIONS_GLOBAL", 1000),
	)
	limiter.redis = client
	return limiter
}

func NewRedisActiveConnectionLimiterFromClient(client *redis.Client) *ActiveConnectionLimiter {
	return NewActiveConnectionLimiterFromClient(client)
}

func (l *ActiveConnectionLimiter) Acquire(organizationID, userID string) (func(), bool) {
	release, _, allowed, _ := l.AcquireContext(context.Background(), organizationID, userID)
	return release, allowed
}

func (l *ActiveConnectionLimiter) AcquireContext(ctx context.Context, organizationID, userID string) (func(), func(context.Context) error, bool, error) {
	organizationID = strings.TrimSpace(organizationID)
	userID = strings.TrimSpace(userID)
	if l == nil || organizationID == "" || userID == "" {
		return nil, nil, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if l.redis != nil {
		return l.acquireRedis(ctx, organizationID, userID)
	}

	return l.acquireLocal(organizationID, userID)
}

func (l *ActiveConnectionLimiter) acquireLocal(organizationID, userID string) (func(), func(context.Context) error, bool, error) {
	l.mu.Lock()
	if l.globalCount >= l.globalLimit || l.tenants[organizationID] >= l.perTenantLimit || l.users[organizationID+":"+userID] >= l.perUserLimit {
		l.mu.Unlock()
		return nil, nil, false, nil
	}
	l.globalCount++
	l.tenants[organizationID]++
	userKey := organizationID + ":" + userID
	l.users[userKey]++
	l.mu.Unlock()

	released := false
	release := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true
		l.globalCount--
		l.tenants[organizationID]--
		l.users[userKey]--
		if l.tenants[organizationID] == 0 {
			delete(l.tenants, organizationID)
		}
		if l.users[userKey] == 0 {
			delete(l.users, userKey)
		}
	}
	return release, func(context.Context) error { return nil }, true, nil
}

func (l *ActiveConnectionLimiter) acquireRedis(ctx context.Context, organizationID, userID string) (func(), func(context.Context) error, bool, error) {
	token := uuid.NewString()
	keys := activeConnectionKeys(organizationID, userID)
	leaseSeconds := int(l.leaseTTL / time.Second)
	if leaseSeconds < 1 {
		leaseSeconds = int(activeConnectionLeaseTTL / time.Second)
	}
	acquired, err := redisActiveConnectionAcquireScript.Run(
		ctx,
		l.redis,
		keys,
		token,
		leaseSeconds,
		l.perUserLimit,
		l.perTenantLimit,
		l.globalLimit,
	).Int()
	if err != nil {
		return nil, nil, false, ErrActiveConnectionBackendUnavailable
	}
	if acquired != 1 {
		return nil, nil, false, nil
	}

	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			releaseCtx, cancel := context.WithTimeout(context.Background(), activeConnectionCommandTimeout)
			defer cancel()
			_ = redisActiveConnectionReleaseScript.Run(releaseCtx, l.redis, keys, token).Err()
		})
	}
	renew := func(renewCtx context.Context) error {
		if renewCtx == nil {
			renewCtx = context.Background()
		}
		result, err := redisActiveConnectionRenewScript.Run(renewCtx, l.redis, keys, token, leaseSeconds).Int()
		if err != nil {
			return ErrActiveConnectionBackendUnavailable
		}
		if result != 1 {
			return ErrActiveConnectionLeaseExpired
		}
		return nil
	}
	return release, renew, true, nil
}

func activeConnectionKeys(organizationID, userID string) []string {
	organizationHash := hashLimiterIdentity(organizationID)
	userHash := hashLimiterIdentity(userID)
	const prefix = "scriptureforge:rooms:connections:v1:"
	return []string{
		prefix + "global",
		prefix + "organization:" + organizationHash,
		prefix + "user:" + organizationHash + ":" + userHash,
	}
}

func hashLimiterIdentity(identity string) string {
	hash := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(hash[:])
}

func (l *Limiter) Check(profileName string, identity string) (Result, bool) {
	result, enforced, _ := l.CheckContext(context.Background(), profileName, identity)
	return result, enforced
}

func (l *Limiter) CheckContext(ctx context.Context, profileName string, identity string) (Result, bool, error) {
	if l == nil {
		return Result{Allowed: true}, false, nil
	}
	profile, ok := l.policy.Profiles[profileName]
	if !ok || profile.Limit < 1 || profile.Window <= 0 {
		return Result{Allowed: true}, false, nil
	}
	profile.Name = profileName
	if strings.TrimSpace(identity) == "" {
		identity = "unknown"
	}
	decision, err := l.allowContext(ctx, profile, identity)
	if err != nil {
		return Result{Allowed: false, Limit: profile.Limit, RetryAfter: time.Second, ResetAt: time.Now().Add(time.Second)}, true, err
	}
	return Result{
		Allowed:    decision.allowed,
		Limit:      profile.Limit,
		RetryAfter: decision.retryAfter,
		Remaining:  decision.remaining,
		ResetAt:    decision.resetAt,
	}, true, nil
}

func (l *Limiter) Middleware(profileName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l == nil {
			next.ServeHTTP(w, r)
			return
		}
		profile, ok := l.policy.Profiles[profileName]
		if !ok || profile.Limit < 1 || profile.Window <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		profile.Name = profileName

		started := time.Now()
		decision, err := l.allowContext(r.Context(), profile, identityForRequest(r, profileName))
		if err != nil {
			observability.ObserveDependencyFromContext(r.Context(), "abuse_limiter", profile.Name, "unavailable", time.Since(started))
			writeRateLimitUnavailable(w)
			return
		}
		metricStatus := "allowed"
		if !decision.allowed {
			metricStatus = "limited"
		}
		observability.ObserveDependencyFromContext(r.Context(), "abuse_limiter", profile.Name, metricStatus, time.Since(started))
		writeRateLimitHeaders(w, profile, decision.remaining, decision.resetAt)
		if !decision.allowed {
			writeRateLimitError(w, profile, decision)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) allowContext(ctx context.Context, profile Profile, identity string) (decision, error) {
	if l.redis == nil {
		return l.allow(profile, identity), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	now := time.Now()
	windowMillis := profile.Window.Milliseconds()
	if windowMillis < 1 {
		return decision{}, ErrLimiterBackendUnavailable
	}
	hash := sha256.Sum256([]byte(profile.Name + "\x00" + identity))
	identityHash := hex.EncodeToString(hash[:])
	slot := now.UnixMilli() / windowMillis
	base := "scriptureforge:abuse:v1:" + profile.Name + ":" + strconv.FormatInt(slot, 10)
	keys := []string{
		base + ":identity:" + identityHash,
		base + ":registry",
		base + ":overflow",
	}
	count, err := redisFixedWindowScript.Run(ctx, l.redis, keys, windowMillis, l.maxBuckets).Int()
	if err != nil {
		return decision{}, ErrLimiterBackendUnavailable
	}
	ttl, err := l.redis.PTTL(ctx, keys[0]).Result()
	if err != nil {
		return decision{}, ErrLimiterBackendUnavailable
	}
	if ttl <= 0 {
		ttl, err = l.redis.PTTL(ctx, keys[2]).Result()
		if err != nil {
			return decision{}, ErrLimiterBackendUnavailable
		}
	}
	if ttl <= 0 {
		ttl = profile.Window
	}
	remaining := profile.Limit - count
	if remaining < 0 {
		remaining = 0
	}
	return decision{
		allowed:    count <= profile.Limit,
		retryAfter: ttl,
		remaining:  remaining,
		resetAt:    now.Add(ttl),
	}, nil
}

func (l *Limiter) allow(profile Profile, identity string) decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	key := profile.Name + ":" + identity
	l.pruneExpired(now)
	if _, exists := l.buckets[key]; !exists && len(l.buckets) >= l.maxBuckets {
		key = profile.Name + ":overflow"
	}
	current := l.buckets[key]
	if current.windowEnd.IsZero() || !now.Before(current.windowEnd) {
		windowEnd := now.Add(profile.Window)
		l.buckets[key] = bucket{count: 1, windowEnd: windowEnd}
		return decision{allowed: true, remaining: profile.Limit - 1, resetAt: windowEnd}
	}
	if current.count >= profile.Limit {
		return decision{allowed: false, retryAfter: current.windowEnd.Sub(now), remaining: 0, resetAt: current.windowEnd}
	}
	current.count++
	l.buckets[key] = current
	return decision{allowed: true, remaining: profile.Limit - current.count, resetAt: current.windowEnd}
}

func (l *Limiter) pruneExpired(now time.Time) {
	for key, current := range l.buckets {
		if !current.windowEnd.IsZero() && !now.Before(current.windowEnd) {
			delete(l.buckets, key)
		}
	}
}

func identityForRequest(r *http.Request, profileName string) string {
	if claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims); ok && claims != nil {
		orgID := strings.TrimSpace(claims.OrganizationID)
		userID := strings.TrimSpace(claims.UserID)
		if orgID != "" && userID != "" {
			return "tenant:" + orgID + ":user:" + userID + ":profile:" + profileName
		}
	}

	if trustProxyHeaders() {
		if clientIP := forwardedClientIP(r); clientIP != "" {
			return "ip:" + clientIP + ":profile:" + profileName
		}
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

func trustProxyHeaders() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("TRUST_PROXY_HEADERS")))
	return raw == "true" || raw == "1" || raw == "yes"
}

func forwardedClientIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	for _, candidate := range strings.Split(forwardedFor, ",") {
		if ip := normalizePublicClientIP(candidate); ip != "" {
			return ip
		}
	}
	return normalizePublicClientIP(r.Header.Get("X-Real-IP"))
}

func normalizeClientIP(raw string) string {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}
	ip := net.ParseIP(candidate)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func normalizePublicClientIP(raw string) string {
	normalized := normalizeClientIP(raw)
	if normalized == "" {
		return ""
	}
	ip := net.ParseIP(normalized)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return ""
	}
	return ip.String()
}

func writeRateLimitHeaders(w http.ResponseWriter, profile Profile, remaining int, resetAt time.Time) {
	if remaining < 0 {
		remaining = 0
	}
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(profile.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	if !resetAt.IsZero() {
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
	}
}

func writeRateLimitError(w http.ResponseWriter, profile Profile, d decision) {
	if d.retryAfter < time.Second {
		d.retryAfter = time.Second
	}
	w.Header().Set("Content-Type", "application/json")
	writeRateLimitHeaders(w, profile, 0, d.resetAt)
	w.Header().Set("Retry-After", strconv.Itoa(int(d.retryAfter.Round(time.Second).Seconds())))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(rateLimitError{
		Category: "ABUSE_RATE_LIMIT_FAULT",
		Message:  "rate limit exceeded for " + profile.Name,
		Code:     http.StatusTooManyRequests,
	})
}

func writeRateLimitUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(rateLimitError{
		Category: "ABUSE_LIMITER_UNAVAILABLE",
		Message:  "rate limiter temporarily unavailable",
		Code:     http.StatusServiceUnavailable,
	})
}
