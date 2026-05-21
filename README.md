# ScriptureForge Architecture Fixes

Applied architectural fixes for performance and high stress workloads.

*   **Database Connection Pooling:** Implemented aggressive connection pooling in `internal/adapters/database_postgres/pgxpool_init.go` to handle massive concurrent connection requests using `pgxpool`.
*   **Circuit Breaking:** Implemented circuit breakers using `sony/gobreaker` in `internal/ports/circuit_breaker.go` to fast fail requests returning `PlatformException` (503 HTTP status) when latency exceeds 2 seconds.
*   **Read Scaling:** Offloaded read-heavy Vector searches to dedicated read-replicas. Infrastructure is configured via `build/terraform/main.tf` to spin up a read-replica. Application routing logic implemented in `internal/domain/bible/repository.go` using a separate `readPool`.
