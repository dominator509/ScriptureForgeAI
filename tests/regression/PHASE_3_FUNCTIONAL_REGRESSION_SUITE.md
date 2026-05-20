# PHASE 3: FUNCTIONAL & SYSTEM INTEGRATION REGRESSION SUITE

## 1. Execution Context
This document defines the critical functional boundaries and edge-case verifications for End-to-End System Integration. These tests must execute upon code instantiation to ensure zero degradation of the defined system contracts.

## 2. E2E Legacy Journey Tests (Complex Intersections)

### 2.1 Multi-Tier Study Generation (AI Orchestrator -> DB -> Frontend)
*   **Test Case ID:** `E2E-RAG-001`
*   **Objective:** Validate that the AI engine correctly generates a youth-focused Bible study from James 1:2-8 without hallucinating non-biblical references.
*   **Action:** Trigger `POST /api/v1/ai/generate/study` with a valid Moderator JWT. Provide prompt context restricting the output to Reformed theology.
*   **Expected Assertion:**
    *   Response status `200 OK`.
    *   Response verification matching subsystem confirms 100% of generated citations exist in `scripture_texts`.
    *   Payload returned conforms to structured JSON (no plain text dumps).
    *   DB stores the `GeneratedAsset` with the correct `organization_id`.

### 2.2 Live Room Sync & External Webhook Handling
*   **Test Case ID:** `E2E-SYNC-002`
*   **Objective:** Validate WebSocket state synchronization across multiple clients when a Zoom room is active, and ensure secure webhook reception.
*   **Action:**
    1.  Host triggers `POST /api/v1/rooms/create`.
    2.  System stubs Zoom API webhook firing back to backend with valid and invalid HMAC SHA256 signatures.
    3.  Three mock clients connect via `WSS /api/v1/rooms/stream/{room_id}`.
    4.  Host mutates state (e.g., changes current verse focus).
*   **Expected Assertion:**
    *   Invalid HMAC SHA256 webhook signatures are rejected with a 401 Unauthorized status.
    *   Single-threaded Redis Lua scripts process the mutation sequentially.
    *   All three clients receive the precise payload mutation simultaneously.
    *   Token authorization during the WSS upgrade correctly rejects a mock client using an expired JWT.

### 2.3 Edge Case & Data Integrity Validations
*   **Test Case ID:** `EDGE-AUTH-003` (Malformed Automation Payload)
*   **Objective:** Ensure the system does not crash or escalate privileges when provided with invalid JWT structures or null tenant IDs.
*   **Action:** Send `POST /api/v1/workspaces/switch` with a malformed `organization_id` (e.g., "DROP TABLE users;") and missing header claims.
*   **Expected Assertion:**
    *   Middleware correctly identifies payload as `CategorySecurity` (`SECURITY_AUTHORIZATION_DENIAL`).
    *   System returns standard `PlatformException` (e.g., Code 401/403) without exposing stack traces.

*   **Test Case ID:** `EDGE-DATA-004` (Integer Overflow in Morphology)
*   **Objective:** Validate the Rust Scripture Engine handles exceptionally large verse or book numbers safely.
*   **Action:** Send gRPC request to Rust service with `book_number: 9999999999`.
*   **Expected Assertion:**
    *   Rust service handles bounds checking correctly and returns a graceful `CategoryData` error rather than faulting the application or corrupting memory.

## 3. Mandatory State Isolation Protocol
When executing these integration suites, the test runner must initialize a dedicated temporary PostgreSQL schema and ephemeral Redis keyspace. Post-execution, the runner must drop these data structures entirely. Live external API endpoints (Zoom, AI Providers) must use localized deterministic mock adapters (e.g., returning predefined JSON payloads) to prevent live environment pollution.
