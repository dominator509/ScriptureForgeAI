package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// APIEnvelope standardizes all JSON egress
type APIEnvelope struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// FieldViolation represents a specific validation failure on a field
type FieldViolation struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// PlatformException represents the standardized error taxonomy
type PlatformException struct {
	Code            string           `json:"code"`
	Message         string           `json:"message"`
	Details         string           `json:"details,omitempty"`
	FieldViolations []FieldViolation `json:"fieldViolations,omitempty"`
}

func (e *PlatformException) Error() string {
	return e.Message
}

// WriteSuccess standardizes successful API responses
func WriteSuccess(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIEnvelope{
		Success: true,
		Data:    data,
	})
}

// HandleError standardizes error API responses
func HandleError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	if pe, ok := err.(*PlatformException); ok {
		status := http.StatusBadRequest
		if pe.Code == "ERR_UNAUTHORIZED" {
			status = http.StatusUnauthorized
		} else if pe.Code == "ERR_RATE_LIMIT" {
		    status = http.StatusTooManyRequests
            // Implement explicit header transparency for rate limiting
            w.Header().Set("Retry-After", "30")
		}

		w.WriteHeader(status)
		json.NewEncoder(w).Encode(APIEnvelope{
			Success: false,
			Error:   pe,
		})
		return
	}

	// Fallback generic error
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(APIEnvelope{
		Success: false,
		Error: map[string]string{
			"code": "ERR_INTERNAL",
			"message": "Internal Server Error",
		},
	})
}

// Simulated Handlers
func createStudyPlanHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate validation failure
	err := &PlatformException{
		Code:    "ERR_VALIDATION_FAILED",
		Message: "The provided payload is invalid.",
		FieldViolations: []FieldViolation{
			{Field: "topic", Reason: "required"},
		},
	}
	HandleError(w, err)
}

func zoomWebhookHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate HMAC failure
	err := &PlatformException{
		Code:    "ERR_UNAUTHORIZED",
		Message: "Webhook signature verification failed.",
		Details: "Missing 'x-zm-signature' header. Payload must be signed using HMAC SHA-256 against ZOOM_WEBHOOK_SECRET_TOKEN.",
	}
	HandleError(w, err)
}

func globalSearchHandler(w http.ResponseWriter, r *http.Request) {
    // Simulate rate limiting transparency on debounced search
    err := &PlatformException{
        Code: "ERR_RATE_LIMIT",
        Message: "Too many search requests.",
        Details: "Please wait 30 seconds before searching again.",
    }
    HandleError(w, err)
}

func main() {
	http.HandleFunc("/api/v1/study-plans", createStudyPlanHandler)
	http.HandleFunc("/api/v1/webhooks/zoom", zoomWebhookHandler)
    http.HandleFunc("/api/v1/search", globalSearchHandler)

	fmt.Println("Starting mock platform engine on :8080")
	http.ListenAndServe(":8080", nil)
}
