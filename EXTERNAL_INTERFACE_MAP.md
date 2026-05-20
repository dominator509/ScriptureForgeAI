# External Interface Map: ScriptureForge AI Backend API

This document maps all public boundaries exposed by the `platform-engine` backend for external interaction based on routing configurations in `cmd/platform-engine/main.go` and associated port controllers.

## 1. Authentication Interface

### `POST /api/auth/register`
*   **Description:** Registers a new user.
*   **Authorization:** None (Public)
*   **Input Payload (JSON):**
    ```json
    {
      "email": "user@example.com",
      "password": "strongPassword123",
      "organization_id": "org-uuid-1234"
    }
    ```
    *   `email`: Must match standard email regex.
    *   `password`: Minimum length 8 characters.
    *   `organization_id`: Must be provided.
*   **Output payload (JSON) - Success (201 Created):**
    ```json
    {
      "token": "jwt-token-string",
      "user_id": "user-uuid"
    }
    ```
*   **Error Responses:** 400 Bad Request, 405 Method Not Allowed, 409 Conflict, 500 Internal Server Error.

### `POST /api/auth/login`
*   **Description:** Authenticates an existing user and returns a JWT.
*   **Authorization:** None (Public)
*   **Input Payload (JSON):**
    ```json
    {
      "email": "user@example.com",
      "password": "strongPassword123"
    }
    ```
*   **Output payload (JSON) - Success (200 OK):**
    ```json
    {
      "token": "jwt-token-string",
      "user_id": "user-uuid"
    }
    ```
*   **Error Responses:** 400 Bad Request, 401 Unauthorized, 405 Method Not Allowed, 500 Internal Server Error.

---

## 2. Artificial Intelligence Interface

### `POST /api/ai/curriculum`
*   **Description:** Generates an AI curriculum based on a topic utilizing MapReduce chunking and RAG.
*   **Authorization:** Bearer Token (JWT required via RBAC middleware). Any role (`member`, etc.) appears to have access currently.
*   **Input Payload (JSON):**
    ```json
    {
      "topic": "Theology of Grace in Galatians"
    }
    ```
    *   `topic`: Must not be empty.
*   **Output payload (JSON) - Success (200 OK):**
    ```json
    {
      "generated_curriculum": "Full text response..."
    }
    ```
*   **Error Responses:** 400 Bad Request, 401 Unauthorized, 405 Method Not Allowed, 500 Internal Server Error.

---

## 3. Webhook Interface

### `POST /api/webhooks/zoom`
*   **Description:** Receives events from Zoom for Live Room sync.
*   **Authorization:** Zoom HMAC SHA256 Signature verification (`x-zm-signature` and `x-zm-request-timestamp` headers against `ZOOM_WEBHOOK_SECRET_TOKEN`).
*   **Input Payload (JSON):**
    ```json
    {
      "event": "meeting.started",
      "payload": {
        "object": {
          "id": "meeting-id",
          "topic": "topic",
          "start_time": "time"
        }
      }
    }
    ```
*   **Output payload:** Empty body, HTTP status indicates success.
*   **Error Responses:** 400 Bad Request, 401 Unauthorized.

---

## 4. WebSocket Interface

### `GET /ws/room` (Upgrades to WebSocket)
*   **Description:** Initiates a live WebSocket connection to a study room.
*   **Authorization:** Bearer Token (JWT required via RBAC middleware).
*   **Input Protocol:** WebSocket protocol upgrade request.
*   **Output Protocol:** WebSocket streams.
