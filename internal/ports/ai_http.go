package ports

import (
	"encoding/json"
	"net/http"
	"regexp"

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

func sendAIError(w http.ResponseWriter, pe *ai.PlatformException) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(pe.Code)
	json.NewEncoder(w).Encode(pe)
}

var auditCitationRegex = regexp.MustCompile(`\[([a-zA-Z\s]+)\s(\d+):(\d+)\]`)

func (h *AIHandler) writeAIRequestLog(r *http.Request, claims *auth.TokenClaims, prompt, status, errorMessage, response string) {
	if h.DB == nil {
		return
	}
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		return
	}
	defer tx.Rollback(r.Context())
	if err := auth.SetTenantContext(r.Context(), tx, claims.OrganizationID); err != nil {
		return
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
		return
	}
	for _, match := range auditCitationRegex.FindAllString(response, -1) {
		_, _ = tx.Exec(
			r.Context(),
			`INSERT INTO citation_trails (organization_id, ai_request_log_id, citation, verified)
			 VALUES ($1, $2, $3, TRUE)`,
			claims.OrganizationID,
			logID,
			match,
		)
	}
	_ = tx.Commit(r.Context())
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

	var req CurriculumRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendAIError(w, &ai.PlatformException{Category: "PAYLOAD_FAULT", Message: "Invalid request payload", Code: http.StatusBadRequest})
		return
	}

	if req.Topic == "" {
		sendAIError(w, &ai.PlatformException{Category: "VALIDATION_FAULT", Message: "Topic is required", Code: http.StatusBadRequest})
		return
	}

	// 1. MapReduce Chunk Processing
	// If the topic is an extensive textual outline, we divide it to protect context windows.
	chunks := h.MapReduceWorker.Chunk(req.Topic)
	var completeCurriculum string

	for _, chunk := range chunks {
		// 2. RAG Compilation per chunk
		compiledContext, err := h.RAGEngine.CompileContext(r.Context(), claims.OrganizationID, chunk)
		if err != nil {
			h.writeAIRequestLog(r, claims, chunk, "failed", err.Error(), "")
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
			h.writeAIRequestLog(r, claims, chunk, "failed", err.Error(), "")
			if pe, ok := err.(*ai.PlatformException); ok {
				sendAIError(w, pe)
			} else {
				sendAIError(w, &ai.PlatformException{Category: "AI_ORCHESTRATION_ENGINE_FAULT", Message: "Model inference or verification failed", Code: 500})
			}
			return
		}

		completeCurriculum += response + "\n\n"
		h.writeAIRequestLog(r, claims, chunk, "succeeded", "", response)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"generated_curriculum": completeCurriculum})
}
