package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// PlatformException represents the standardized error taxonomy
type PlatformException struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *PlatformException) Error() string {
	return e.Message
}

// Simulated Error Mapper
func HandleError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	if pe, ok := err.(*PlatformException); ok {
		w.WriteHeader(http.StatusBadRequest) // Simplified for mock
		json.NewEncoder(w).Encode(pe)
		return
	}

	// Fallback generic error
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "Internal Server Error",
	})
}

// Simulated Handlers
func createStudyPlanHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate validation failure
	err := &PlatformException{
		Code:    "ERR_VALIDATION_FAILED",
		Message: "The provided payload is invalid.",
		Details: "Missing required field: 'topic'",
	}
	HandleError(w, err)
}

func zoomWebhookHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate HMAC failure
	err := &PlatformException{
		Code:    "ERR_UNAUTHORIZED",
		Message: "Webhook signature verification failed.",
	}
	HandleError(w, err)
}

func main() {
	http.HandleFunc("/api/v1/study-plans", createStudyPlanHandler)
	http.HandleFunc("/api/v1/webhooks/zoom", zoomWebhookHandler)

	fmt.Println("Starting mock platform engine on :8080")
	http.ListenAndServe(":8080", nil)
}
