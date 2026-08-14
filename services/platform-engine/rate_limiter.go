package main

import (
	"sync"
	"time"
)

type IPRateTracker struct {
	mu            sync.Mutex
	Window5MinStart time.Time
	Window1MinStart time.Time
	ReqCount1Min  int
	ReqCount5Min  int
	IsBlocked     bool
	LastActive    time.Time
}

type AccountTracker struct {
	mu             sync.Mutex
	FailedAttempts int
	LastFailed     time.Time
	IsLocked       bool
}

type RateLimiter struct {
	ipMap      sync.Map // key: ip string
	accountMap sync.Map // key: email string
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{}
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()

		rl.ipMap.Range(func(key, value interface{}) bool {
			tracker := value.(*IPRateTracker)
			tracker.mu.Lock()
			// Evict if not blocked and inactive for 10 minutes
			if !tracker.IsBlocked && now.Sub(tracker.LastActive) > 10*time.Minute {
				tracker.mu.Unlock()
				rl.ipMap.Delete(key)
				return true
			}
			tracker.mu.Unlock()
			return true
		})

		rl.accountMap.Range(func(key, value interface{}) bool {
			tracker := value.(*AccountTracker)
			tracker.mu.Lock()
			// Evict if inactive for 1 hour
			if now.Sub(tracker.LastFailed) > 1*time.Hour {
				tracker.mu.Unlock()
				rl.accountMap.Delete(key)
				return true
			}
			tracker.mu.Unlock()
			return true
		})
	}
}

func (rl *RateLimiter) CheckIP(ip string) (allowed bool, message string) {
	now := time.Now()
	val, _ := rl.ipMap.LoadOrStore(ip, &IPRateTracker{
		Window5MinStart: now,
		Window1MinStart: now,
		LastActive:      now,
	})
	tracker := val.(*IPRateTracker)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.LastActive = now

	if tracker.IsBlocked {
		return false, "IP permanently blocked. Disable proxy or VPN to use this service."
	}

	// 5-minute window logic
	if now.Sub(tracker.Window5MinStart) > 5*time.Minute {
		tracker.Window5MinStart = now
		tracker.ReqCount5Min = 0
	}

	// 1-minute window logic
	if now.Sub(tracker.Window1MinStart) > 1*time.Minute {
		tracker.Window1MinStart = now
		tracker.ReqCount1Min = 0
	}

	tracker.ReqCount1Min++
	tracker.ReqCount5Min++

	if tracker.ReqCount5Min > 1000 {
		tracker.IsBlocked = true
		return false, "IP permanently blocked. Disable proxy or VPN to use this service."
	}

	if tracker.ReqCount1Min > 5 {
		return false, "Too many requests. Please try again later."
	}

	return true, ""
}

// IsAccountLocked checks if the account is already locked without incrementing attempts.
func (rl *RateLimiter) IsAccountLocked(email string) bool {
	val, ok := rl.accountMap.Load(email)
	if !ok {
		return false
	}
	tracker := val.(*AccountTracker)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.IsLocked
}

// RecordAccountAttempt records an attempt and returns the current state.
func (rl *RateLimiter) RecordAccountAttempt(email string, success bool) (warningMsg string, locked bool) {
	now := time.Now()
	val, _ := rl.accountMap.LoadOrStore(email, &AccountTracker{
		LastFailed: now,
	})
	tracker := val.(*AccountTracker)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if tracker.IsLocked {
		return "", true
	}

	if success {
		tracker.FailedAttempts = 0
		return "", false
	}

	if tracker.FailedAttempts > 0 && now.Sub(tracker.LastFailed) > 1*time.Hour {
		tracker.FailedAttempts = 0
	}

	tracker.FailedAttempts++
	tracker.LastFailed = now

	if tracker.FailedAttempts >= 5 {
		tracker.IsLocked = true
		return "", true
	}

	if tracker.FailedAttempts == 3 {
		return "2 attempts remaining before lockout", false
	}
	if tracker.FailedAttempts == 4 {
		return "1 attempt remaining before lockout", false
	}

	return "", false
}
