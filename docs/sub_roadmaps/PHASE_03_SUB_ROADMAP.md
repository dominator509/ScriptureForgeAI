# Phase 03: Rust Scripture Engine - Sub-Roadmap

## Overview
Code the optimized lexical processing service to coordinate fast morphologic analysis and vector matching operations safely.

## Immediate Task Constraints
*   Strict adherence to `SF-architecture.md` and `SF-roadmap.md`.
*   Zero functional application code or schemas may be written prior to the validation of this sub-roadmap.
*   Loose types (`any` in TS, `interface{}` in Go) are blocked.
*   All errors must be typed and mapped to `PlatformException`.

## Step-by-Step Implementation Tasks

### 1. Protocol Buffer Interface Contracts
*   **Target File:** `/proto/scripture.proto`
*   **Action:** Author core protobuf definitions mapping structural parameters for textual queries, morphologic tracking variables, and multi-dimensional vector inputs.

### 2. Rust Workspace Initialization
*   **Target Path:** `/services/scripture-engine/`
*   **Action:** Initialize the dedicated Rust compilation workspace. Configure framework extensions (`tonic`) and map automated gRPC code injection profiles.

### 3. gRPC Server Integration
*   **Target File:** `/services/scripture-engine/src/server.rs`
*   **Action:** Implement the Tonic gRPC server binding to the generated protobuf contracts, handling incoming queries safely.

### 4. Vector Retrieval Handlers
*   **Target File:** `/services/scripture-engine/src/db.rs`
*   **Action:** Implement memory-safe handlers connecting to the PostgreSQL database to perform fast vector retrieval operations via pgvector.

## Testing & Acceptance Criteria
*   **Acceptance:** The Rust service successfully compiles, binds to a gRPC port, and handles incoming protobuf messages without memory leaks or unsafe pointer panics. Vector operations successfully retrieve matching database rows.
*   **Integration Tests:** Construct tests verifying gRPC communication paths and validating accurate semantic vector search results from the database.
*   **Security Checks:** Ensure the Rust service has isolated network boundaries and does not expose direct unauthenticated access to the database layer.
