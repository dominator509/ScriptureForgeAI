package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"scriptureforge/internal/domain/observability"
)

type contextKey string

const (
	ContextKeyUser contextKey = "user_claims"
)

// RBACMiddleware intercepts incoming HTTP requests to validate JWTs and authorize access.
// It maps the validated TokenClaims into the request context for downstream handlers.
func RBACMiddleware(next http.Handler, requiredRole string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser WebSocket clients cannot set Authorization headers, so allow a
		// temporary ticket only on the room stream route. All other routes require
		// the bearer header and never treat arbitrary query data as credentials.
		authHeader := r.Header.Get("Authorization")
		var tokenString string

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/stream/") {
			tokenString = r.URL.Query().Get("ticket")
		}

		if tokenString == "" {
			sendError(w, &PlatformException{
				Category: AuthenticationFault,
				Message:  "missing or invalid authorization token",
				Code:     http.StatusUnauthorized,
			})
			return
		}

		claims, err := ValidateToken(tokenString)
		if err != nil {
			if pe, ok := err.(*PlatformException); ok {
				sendError(w, pe)
			} else {
				sendError(w, &PlatformException{
					Category: AuthenticationFault,
					Message:  "invalid token",
					Code:     http.StatusUnauthorized,
				})
			}
			return
		}

		// Check RBAC Role if a specific role is required
		if requiredRole != "" && claims.Role != requiredRole && claims.Role != "admin" {
			sendError(w, &PlatformException{
				Category: AuthorizationFault,
				Message:  fmt.Sprintf("user role '%s' lacks required permission '%s'", claims.Role, requiredRole),
				Code:     http.StatusForbidden,
			})
			return
		}

		// Inject verified claims into the request context to eliminate parameter spoofing
		observability.EnrichRequestLogFields(r.Context(), claims.OrganizationID, claims.UserID, claims.Role)
		ctx := context.WithValue(r.Context(), ContextKeyUser, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sendError(w http.ResponseWriter, pe *PlatformException) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.Code)
	// Use proper json encoding to avoid malformed json from string injection
	json.NewEncoder(w).Encode(pe)
}
