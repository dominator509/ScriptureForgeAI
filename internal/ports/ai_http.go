package ports

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/auth"
)

type AIHandler struct {
	DB              *pgxpool.Pool
	RAGEngine       *ai.RAGEngine
	Verifier        *ai.ResponseVerificationSubsystem
	LLMClient       *llm.LLMClient
	MapReduceWorker *ai.MapReduceWorker
}

type CurriculumRequest struct {
	Topic string `json:"topic"`
}

const (
	maxAIRequestBodyBytes = 64 * 1024
	maxAITopicCharacters  = 16 * 1024
	maxAIChunks           = 64
)

func sendAIError(w http.ResponseWriter, pe *ai.PlatformException) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.Code)
	json.NewEncoder(w).Encode(pe)
}

var auditCitationRegex = regexp.MustCompile(`\[([a-zA-Z\s]+)\s(\d+):(\d+)\]`)

func (h *AIHandler) writeAIRequestLog(r *http.Request, claims *auth.TokenClaims, prompt, status, errorMessage, response string) error {
	if h.DB == nil {
		return errors.New("AI audit database is not configured")
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		return err
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		return err
	}
	var logID string
	err = tx.QueryRow(
		r.Context(),
		`INSERT INTO ai_request_logs (organization_id, user_id, prompt, status, error_message)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		claims.OrganizationID,
		claims.UserID,
		prompt,
		status,
		errorMessage,
	).Scan(&logID)
	if err != nil {
		return err
	}
	for _, match := range auditCitationRegex.FindAllString(response, -1) {
		if _, err := tx.Exec(
			r.Context(),
			`INSERT INTO citation_trails (organization_id, ai_request_log_id, citation, verified)
			 VALUES ($1, $2, $3, TRUE)`,
			claims.OrganizationID,
			logID,
			match,
		); err != nil {
			return err
		}
	}
	return tx.Commit(r.Context())
}

func (h *AIHandler) generationDependenciesReady() bool {
	return h.DB != nil && h.RAGEngine != nil && h.Verifier != nil && h.LLMClient != nil && h.MapReduceWorker != nil
}

func aiAuditPersistenceFault() *ai.PlatformException {
	return &ai.PlatformException{Category: "AI_AUDIT_FAULT", Message: "AI audit persistence is unavailable", Code: http.StatusServiceUnavailable}
}

func (h *AIHandler) GenerateCurriculumHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendAIError(w, &ai.PlatformException{Category: "ROUTING_FAULT", Message: "Method not allowed", Code: http.StatusMethodNotAllowed})
		return
	}

	claims, ok := r.Context().Value(auth.ContextKeyUser).(*auth.TokenClaims)
	if !ok || claims == nil {
		sendAIError(w, &ai.PlatformException{Category: "AUTHORIZATION_FAULT", Message: "Unauthorized access", Code: http.StatusUnauthorized})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAIRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req CurriculumRequest
	if err := decoder.Decode(&req); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			sendAIError(w, &ai.PlatformException{Category: "PAYLOAD_FAULT", Message: "AI request payload is too large", Code: http.StatusRequestEntityTooLarge})
			return
		}
		sendAIError(w, &ai.PlatformException{Category: "PAYLOAD_FAULT", Message: "Invalid request payload", Code: http.StatusBadRequest})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		sendAIError(w, &ai.PlatformException{Category: "PAYLOAD_FAULT", Message: "Invalid request payload", Code: http.StatusBadRequest})
		return
	}

	if req.Topic == "" {
		sendAIError(w, &ai.PlatformException{Category: "VALIDATION_FAULT", Message: "Topic is required", Code: http.StatusBadRequest})
		return
	}
	if utf8.RuneCountInString(req.Topic) > maxAITopicCharacters {
		sendAIError(w, &ai.PlatformException{Category: "VALIDATION_FAULT", Message: "Topic exceeds the maximum length", Code: http.StatusRequestEntityTooLarge})
		return
	}
	if !h.generationDependenciesReady() {
		sendAIError(w, &ai.PlatformException{Category: "AI_CONFIGURATION_FAULT", Message: "AI generation dependencies are not configured", Code: http.StatusServiceUnavailable})
		return
	}

	// 1. MapReduce Chunk Processing
	// If the topic is an extensive textual outline, we divide it to protect context windows.
	chunks := h.MapReduceWorker.Chunk(req.Topic)
	if len(chunks) > maxAIChunks {
		sendAIError(w, &ai.PlatformException{Category: "VALIDATION_FAULT", Message: "Topic produces too much work", Code: http.StatusRequestEntityTooLarge})
		return
	}
	var completeCurriculum string

	for _, chunk := range chunks {
		// 2. RAG Compilation per chunk
		compiledContext, err := h.RAGEngine.CompileContext(r.Context(), claims.OrganizationID, chunk)
		if err != nil {
			if auditErr := h.writeAIRequestLog(r, claims, chunk, "failed", err.Error(), ""); auditErr != nil {
				sendAIError(w, aiAuditPersistenceFault())
				return
			}
			if pe, ok := err.(*ai.PlatformException); ok {
				sendAIError(w, pe)
			} else {
				sendAIError(w, &ai.PlatformException{Category: "AI_ORCHESTRATION_ENGINE_FAULT", Message: "Failed to compile semantic context", Code: 500})
			}
			return
		}

		// 3. Execute via explicit boundaries and strict response verification per chunk
		response, err := h.LLMClient.Execute(r.Context(), chunk, compiledContext, h.Verifier)
		if err != nil {
			if auditErr := h.writeAIRequestLog(r, claims, chunk, "failed", err.Error(), ""); auditErr != nil {
				sendAIError(w, aiAuditPersistenceFault())
				return
			}
			if pe, ok := err.(*ai.PlatformException); ok {
				sendAIError(w, pe)
			} else {
				sendAIError(w, &ai.PlatformException{Category: "AI_ORCHESTRATION_ENGINE_FAULT", Message: "Model inference or verification failed", Code: 500})
			}
			return
		}

		completeCurriculum += response + "\n\n"
		if auditErr := h.writeAIRequestLog(r, claims, chunk, "succeeded", "", response); auditErr != nil {
			sendAIError(w, aiAuditPersistenceFault())
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"generated_curriculum": completeCurriculum})
}
