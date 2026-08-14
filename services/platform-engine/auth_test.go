package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	// Worker pool of 1, queue size 1
	wp := NewWorkerPool(1, 1)

	// Fill the worker and the queue
	ctx := context.Background()

	var wg sync.WaitGroup

	// Task 1: taken by worker (blocks until hashed)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = wp.HashPassword(ctx, "pass1", []byte("salt"))
	}()
	time.Sleep(10 * time.Millisecond) // Give worker time to pick up

	// Task 2: placed in queue of size 1
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = wp.HashPassword(ctx, "pass2", []byte("salt"))
	}()
	time.Sleep(10 * time.Millisecond) // Give time to enter queue

	// Task 3: should fail fast because worker is busy and queue is full
	_, err := wp.HashPassword(ctx, "pass3", []byte("salt"))
	if err != ErrHashingQueueFull {
		t.Errorf("Expected ErrHashingQueueFull, got %v", err)
	}

	wg.Wait()
}

func TestRateLimiter_AccountLockout(t *testing.T) {
	rl := NewRateLimiter()
	email := "test@example.com"

	// 1 fail
	w, l := rl.RecordAccountAttempt(email, false)
	if w != "" || l != false {
		t.Errorf("Expected no warning/lock on fail 1, got %s, %v", w, l)
	}

	// 2 fails
	rl.RecordAccountAttempt(email, false)

	// 3 fails -> warning
	w, l = rl.RecordAccountAttempt(email, false)
	if !strings.Contains(w, "2 attempts remaining") || l != false {
		t.Errorf("Expected warning on fail 3, got %s, %v", w, l)
	}

	// 4 fails -> warning
	w, l = rl.RecordAccountAttempt(email, false)
	if !strings.Contains(w, "1 attempt remaining") || l != false {
		t.Errorf("Expected warning on fail 4, got %s, %v", w, l)
	}

	// 5 fails -> locked
	w, l = rl.RecordAccountAttempt(email, false)
	if l != true {
		t.Errorf("Expected lock on fail 5, got %v", l)
	}
}

func TestRateLimiter_IPLimit(t *testing.T) {
	rl := NewRateLimiter()
	ip := "127.0.0.1"

	// 5 requests allowed
	for i := 0; i < 5; i++ {
		allowed, _ := rl.CheckIP(ip)
		if !allowed {
			t.Errorf("Expected request %d to be allowed", i+1)
		}
	}

	// 6th request should be blocked temporarily
	allowed, _ := rl.CheckIP(ip)
	if allowed {
		t.Errorf("Expected 6th request to be blocked")
	}

	// Override tracker to test permanent block (>1000 in 5 mins)
	trackerVal, _ := rl.ipMap.Load(ip)
	tracker := trackerVal.(*IPRateTracker)
	tracker.mu.Lock()
	tracker.ReqCount5Min = 1000
	tracker.mu.Unlock()

	allowed, msg := rl.CheckIP(ip)
	if allowed || !strings.Contains(msg, "VPN") {
		t.Errorf("Expected permanent block message, got allowed=%v, msg=%s", allowed, msg)
	}
}

func TestAuthHandlers(t *testing.T) {
	// Initialize system
	initAuthSystem()

	// Login Route Test
	reqBody := []byte(`{"email":"test@example.com", "password":"wrongpassword"}`)
	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
	// We must create a new request reader for each HTTP call, otherwise body is empty
	req.Header.Set("X-Forwarded-For", "192.168.1.1")

	// Fail 1
	rr := httptest.NewRecorder()
	handleLogin(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rr.Code)
	}

	// Fail 2
	rr2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
	req2.Header.Set("X-Forwarded-For", "192.168.1.1")
	handleLogin(rr2, req2)

	// Fail 3 (Should get warning)
	rr3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
	req3.Header.Set("X-Forwarded-For", "192.168.1.1")
	handleLogin(rr3, req3)
	var resp AuthResponse
	json.NewDecoder(rr3.Body).Decode(&resp)
	if resp.Warning == "" {
		t.Errorf("Expected warning on 3rd fail")
	}
}
