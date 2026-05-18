package ports

import (
	"encoding/json"
	"net/http"

	"scriptureforge/internal/adapters/llm"
	"scriptureforge/internal/domain/ai"
	"scriptureforge/internal/domain/auth"
)

type AIHandler struct {
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
			if pe, ok := err.(*ai.PlatformException); ok {
				sendAIError(w, pe)
			} else {
				sendAIError(w, &ai.PlatformException{Category: "AI_ORCHESTRATION_ENGINE_FAULT", Message: "Model inference or verification failed", Code: 500})
			}
			return
		}

		completeCurriculum += response + "\n\n"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"generated_curriculum": completeCurriculum})
}
