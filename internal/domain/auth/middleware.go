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

const RoomWebSocketSubprotocol = "scriptureforge-bearer"

// SessionValidator lets the transport layer enforce server-side logout cutoffs
// after the JWT has passed signature and claim validation.
type SessionValidator func(context.Context, *TokenClaims) error

func isMFAEnrollmentPath(path string) bool {
	return path == "/api/v1/auth/mfa/enroll" || path == "/api/v1/auth/mfa/verify"
}

func websocketBearerToken(r *http.Request) string {
	protocols := strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",")
	for index := 0; index+1 < len(protocols); index++ {
		if strings.TrimSpace(protocols[index]) == RoomWebSocketSubprotocol {
			return strings.TrimSpace(protocols[index+1])
		}
	}
	return ""
}

// RBACMiddleware intercepts incoming HTTP requests to validate JWTs and authorize access.
// It maps the validated TokenClaims into the request context for downstream handlers.
func RBACMiddleware(next http.Handler, requiredRole string) http.Handler {
	return RBACMiddlewareWithSession(next, requiredRole, nil)
}

// RBACMiddlewareWithSession validates the JWT and, when configured, the
// server-side session state before allowing a protected request to proceed.
func RBACMiddlewareWithSession(next http.Handler, requiredRole string, validator SessionValidator) http.Handler {
	if strings.TrimSpace(requiredRole) == "" {
		return RBACMiddlewareAnyRoleWithSession(next, validator)
	}
	return RBACMiddlewareAnyRoleWithSession(next, validator, requiredRole)
}

// RBACMiddlewareAnyRole protects a route for one of several equivalent roles.
// Role names are normalized so JWTs issued from the documented role vocabulary
// and the lower-case database representation share the same authorization path.
func RBACMiddlewareAnyRole(next http.Handler, requiredRoles ...string) http.Handler {
	return RBACMiddlewareAnyRoleWithSession(next, nil, requiredRoles...)
}

// RBACMiddlewareAnyRoleWithSession is the session-aware form of the role
// middleware. The legacy wrapper remains available for non-database callers.
func RBACMiddlewareAnyRoleWithSession(next http.Handler, validator SessionValidator, requiredRoles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser WebSocket clients cannot set Authorization headers, so accept the
		// short-lived bearer token only in the negotiated room subprotocol header.
		// Query strings are never treated as credentials because proxies commonly log them.
		authHeader := r.Header.Get("Authorization")
		var tokenString string

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/rooms/stream/") {
			tokenString = websocketBearerToken(r)
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
		if claims.MFAEnrollmentOnly && !isMFAEnrollmentPath(r.URL.Path) {
			sendError(w, &PlatformException{
				Category: AuthorizationFault,
				Message:  "MFA enrollment token is restricted to MFA setup",
				Code:     http.StatusForbidden,
			})
			return
		}
		if validator != nil {
			if err := validator(r.Context(), claims); err != nil {
				if pe, ok := err.(*PlatformException); ok {
					sendError(w, pe)
				} else {
					sendError(w, &PlatformException{
						Category: AuthenticationFault,
						Message:  "session validation failed",
						Code:     http.StatusServiceUnavailable,
					})
				}
				return
			}
		}

		allowedRoles := make(map[string]struct{}, len(requiredRoles))
		for _, role := range requiredRoles {
			if normalized := strings.ToLower(strings.TrimSpace(role)); normalized != "" {
				allowedRoles[normalized] = struct{}{}
			}
		}
		// Check RBAC role if one or more specific roles are required. The
		// legacy admin role remains a platform-level override.
		if len(allowedRoles) > 0 {
			_, allowed := allowedRoles[strings.ToLower(strings.TrimSpace(claims.Role))]
			if !allowed && strings.ToLower(strings.TrimSpace(claims.Role)) != "admin" {
				requiredRole := strings.Join(requiredRoles, ",")
				sendError(w, &PlatformException{
					Category: AuthorizationFault,
					Message:  fmt.Sprintf("user role '%s' lacks required permission '%s'", claims.Role, requiredRole),
					Code:     http.StatusForbidden,
				})
				return
			}
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
