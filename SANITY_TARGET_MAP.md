# SANITY_TARGET_MAP

## Overview
This document maps the blast radius of recent code changes to identify the specific execution paths that must be verified during the Golden Path sanity check.

## Recent Delta Analysis
Based on the recent git history (`git log`), the primary modifications occurred in:
1.  **Platform Engine Initialization (`cmd/platform-engine/main.go`)**: Resolution of unused constants and overall code health/initialization improvements.
2.  **Authentication/JWT Configuration (`internal/domain/auth/...`)**: Removal of the hardcoded `JWT_SECRET_KEY` fallback, forcing the system to rely strictly on the environment variable for session generation and validation.

## Target Execution Paths (The Blast Radius)
Because the platform engine ties all subsystems together and the JWT logic is the gatekeeper for all protected routes, the Golden Path verification must traverse the entirety of the system's core functionality.

The target execution paths to be tested are:

1.  **System Initialization & Subsystem Handoff**:
    *   Verify the engine's ability to mock DB/Redis connections and initialize the core `ServeMux` via `setupRoutes()`.

2.  **Authentication Golden Path (Impacted by JWT Change)**:
    *   **Registration** (`POST /api/auth/register`): Verify user creation.
    *   **Login** (`POST /api/auth/login`): Verify password verification and successful JWT token generation using the provided environment variable.

3.  **AI Curriculum Generation Golden Path (Protected Route)**:
    *   **Generation** (`POST /api/ai/curriculum`): Verify that a valid JWT token permits access and that the MapReduce/RAG mocked interfaces are successfully invoked to produce a Bible study plan.

4.  **Zoom Webhook / Room State Golden Path (External Interface)**:
    *   **Webhook Ingestion** (`POST /api/webhooks/zoom`): Verify HMAC validation using `ZOOM_WEBHOOK_SECRET_TOKEN` and confirm room state is updated in Redis (mocked).
