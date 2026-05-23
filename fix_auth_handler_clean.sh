cat << 'INNER_EOF' > services/platform-engine/auth_handler.go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

var (
	hashingWorkerPool *WorkerPool
	authRateLimiter   *RateLimiter
)

func initAuthSystem() {
	hashingWorkerPool = NewWorkerPool(4, 100)
	authRateLimiter = NewRateLimiter()
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Warning string `json:"warning,omitempty"`
	Token   string `json:"token,omitempty"`
}

func getIP(r *http.Request) string {
	// Defends against X-Forwarded-For spoofing. In a real load-balanced environment,
	// this would validate the proxy chain. For this architecture, relying on RemoteAddr
	// ensures we don't blindly trust user headers.
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r)

	// 1. IP Rate Limiting (Pre-Hashing)
	allowed, ipMsg := authRateLimiter.CheckIP(ip)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(AuthResponse{
			Status:  "error",
			Message: ipMsg,
		})
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 2. Check if account is already locked BEFORE hashing
	if authRateLimiter.IsAccountLocked(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(AuthResponse{
			Status:  "locked",
			Message: "Account locked due to excessive failed attempts. Mandatory password recovery required.",
		})
		return
	}

	// Mock retrieving user salt and stored hash from DB
	mockSalt := []byte("somesalt123")

	// 3. Offload to Bounded Hashing Worker Pool
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	hash, err := hashingWorkerPool.HashPassword(ctx, req.Password, mockSalt)
	if err != nil {
		if err == ErrHashingQueueFull {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable) // 503
			json.NewEncoder(w).Encode(AuthResponse{
				Status:  "error",
				Message: "Server overloaded. Please try again later.",
			})
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 4. Validate Credentials (Mock validation)
	isValid := len(hash) > 0 && req.Password == "password123"

	if !isValid {
		warning, locked := authRateLimiter.RecordAccountAttempt(req.Email, false)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		resp := AuthResponse{
			Status:  "error",
			Message: "Invalid credentials",
		}

		if locked {
			resp.Status = "locked"
			resp.Message = "Account locked due to excessive failed attempts. Mandatory password recovery required."
		} else if warning != "" {
			resp.Warning = warning
		}

		json.NewEncoder(w).Encode(resp)
		return
	}

	// Success
	authRateLimiter.RecordAccountAttempt(req.Email, true)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		Status: "success",
		Token:  "mock-jwt-token",
	})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := getIP(r)

	// 1. IP Rate Limiting
	allowed, ipMsg := authRateLimiter.CheckIP(ip)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(AuthResponse{
			Status:  "error",
			Message: ipMsg,
		})
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	salt := []byte("newusersalt")

	// 2. Offload to Bounded Hashing Worker Pool
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	_, err := hashingWorkerPool.HashPassword(ctx, req.Password, salt)
	if err != nil {
		if err == ErrHashingQueueFull {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(AuthResponse{
				Status:  "error",
				Message: "Server overloaded. Please try again later.",
			})
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthResponse{
		Status: "success",
		Message: "User registered successfully",
	})
}
INNER_EOF
