package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	csrfCookieName = "scriptureforge_csrf"
	csrfHeaderName = "X-CSRF-Token"
	csrfTokenBytes = 32
	csrfTokenTTL   = 30 * 24 * time.Hour
)

func generateCSRFToken() (string, error) {
	raw := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validCSRFToken(token string) bool {
	if strings.TrimSpace(token) != token || token == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == csrfTokenBytes
}

func secureBrowserCookie(r *http.Request) bool {
	if requiresConfiguredBrowserOrigins() {
		return true
	}
	return r.TLS != nil
}

func setCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(csrfTokenTTL.Seconds()),
		HttpOnly: false,
		Secure:   secureBrowserCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func csrfTokenMatchesRequest(r *http.Request) bool {
	headerToken := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || !validCSRFToken(headerToken) || !validCSRFToken(cookie.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookie.Value)) == 1
}

func csrfHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	token := ""
	if cookie, err := r.Cookie(csrfCookieName); err == nil && validCSRFToken(cookie.Value) {
		token = cookie.Value
	}
	if token == "" {
		var err error
		token, err = generateCSRFToken()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"csrf_token_unavailable"}`))
			return
		}
	}
	setCSRFCookie(w, r, token)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"csrf_token": token})
}
