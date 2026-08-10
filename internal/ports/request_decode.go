package ports

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"scriptureforge/internal/domain/auth"
)

// decodeBoundedJSON rejects oversized or concatenated request bodies before handlers
// perform database work, password hashing, or base64 decoding.
func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, destination any, category auth.ErrorCategory, message string) *auth.PlatformException {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return &auth.PlatformException{Category: category, Message: message + " is too large", Code: http.StatusRequestEntityTooLarge}
		}
		return &auth.PlatformException{Category: category, Message: message, Code: http.StatusBadRequest}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return &auth.PlatformException{Category: category, Message: message, Code: http.StatusBadRequest}
	}
	return nil
}
