# Phase 02: Auth, RBAC & Zero-Knowledge - Sub-Roadmap

## Overview
Author and integrate robust tenant separation filters, cryptographically sound access controls, and zero-knowledge data containment engines for ScriptureForge AI.

## Immediate Task Constraints
*   Strict adherence to `SF-architecture.md` and `SF-roadmap.md`.
*   Zero functional application code or schemas may be written prior to the validation of this sub-roadmap.
*   Loose types (`any` in TS, `interface{}` in Go) are blocked.
*   All errors must be typed and mapped to `PlatformException`.

## Step-by-Step Implementation Tasks

### 1. Memory-Safe String Hashing
*   **Target Files:** `/internal/domain/auth/`
*   **Action:** Write memory-safe string hashing modules utilizing the Argon2id derivation methodology for secure storage of user authentication strings.

### 2. JWT Parsing & Validation
*   **Target Files:** `/internal/domain/auth/`
*   **Action:** Build core permission token validation wrappers. Ensure issuance of short-lived access structures paired with database-backed opaque tracking records. Implement backend endpoint routers mapping registration parameters and session challenges, strictly filtering via validation rules.

### 3. Backend RBAC Middleware
*   **Target Files:** `/internal/domain/auth/` (and HTTP routing layers)
*   **Action:** Author robust backend permission analysis middleware. This component must intercept inbound API routing paths and implicitly map context requests using verified token metadata parameters to eliminate parameter spoofing vulnerabilities.

### 4. Client-Side Cryptographic Routines (Derivation)
*   **Target Files:** `/pkg/crypto_utils/` or `/web/src/lib/crypto.ts`
*   **Action:** Code browser-compliant cryptographic routines running on client layers. These must construct 256-bit isolation keys via PBKDF2 processing transformations using high iteration values and localized unique data salts.

### 5. Client-Side Cryptographic Routines (Storage & Encryption)
*   **Target Files:** `/web/src/lib/crypto.ts`
*   **Action:** Develop client-side storage processing routines using AES-256-GCM algorithms to seal sensitive personal structural text transformations prior to network transmission vectors. Ensure plain-text decryption credentials vanish from client runtime scopes upon session teardown.

## Testing & Acceptance Criteria
*   **Acceptance:** Users register and authenticate securely, receiving short-duration valid tokens. Route intercepts deny operations failing baseline verification rules. Personal content is transformed into encrypted blocks prior to network ingestion.
*   **Integration Tests:** Construct `/tests/unit/auth_rbac_test.go` to test passing corrupted signatures, expired claims, and altered tenancy identities to assert the filtering engine denies cross-tenant request attempts.
*   **Security Checks:** Enforce strict system validation confirming the backend database stores zero plain-text journal data fragments, handling incoming personal logs strictly as opaque payloads.
