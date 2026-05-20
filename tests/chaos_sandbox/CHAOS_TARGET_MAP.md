# Chaos Target Map

Based on the architectural review and source code discovery, the following are the top 5 most vulnerable subsystems identified for exploratory testing:

1. **JWT RBAC Middleware (`internal/domain/auth/middleware.go` & `internal/domain/auth/jwt.go`)**
   - *Vulnerability:* Improper signature validation, expired token acceptance, or tenant ID extraction failures could lead to cross-tenant data bleeding or unauthorized access.
   - *Exploratory Focus:* Fuzz token claims, modify signatures, and test boundary conditions with missing or malformed JWT headers.

2. **AI RAG & Response Verification Subsystem (`internal/domain/ai/verification.go` & `internal/domain/ai/rag.go`)**
   - *Vulnerability:* The system relies on regex-based matching for citation verification. Malformed or adversarial LLM outputs could bypass these checks or cause panic/hang during regex evaluation.
   - *Exploratory Focus:* Inject deeply nested, infinite string structures or complex malformed text designed to trigger catastrophic backtracking or memory bloat in parsing logic.

3. **WebSocket Real-Time Sync & State Coordinators (`internal/ports/driving_wss.go` & `internal/domain/room/redis_lua.go`)**
   - *Vulnerability:* High-frequency, uncoordinated connection states can lead to race conditions, dropped messages, or Redis state lockups.
   - *Exploratory Focus:* Script rapid-fire concurrent WebSocket connections, abruptly disconnect them, and push malformed synchronization payloads under heavy concurrent load.

4. **MapReduce Text Chunking (`internal/domain/ai/mapreduce.go`)**
   - *Vulnerability:* Handling exceptionally large inputs or malformed text blocks could lead to out-of-bounds array access, infinite loops, or memory exhaustion.
   - *Exploratory Focus:* Fuzz the chunking mechanism with extreme sizes, invalid UTF-8 strings, and unexpected zero-length edge cases.

5. **Zoom Webhook Integration (`internal/adapters/integration_zoom/zoom_webhook.go`)**
   - *Vulnerability:* Inadequate HMAC SHA256 signature verification or processing logic could allow an attacker to spoof zoom events, leading to incorrect state mutations (e.g., falsely starting/ending rooms).
   - *Exploratory Focus:* Send rapid, out-of-order webhook events (e.g., meeting ended before started) and invalid signatures to ensure the system drops them safely without side-effects.
