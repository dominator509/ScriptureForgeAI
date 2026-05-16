# Phase 01: Infrastructure & Data Core - Sub-Roadmap

## Overview
Establish the persistent multi-tenant data layer, active caching engines, and baseline infrastructure-as-code automation definitions for ScriptureForge AI (BibleStudyOS).

## Immediate Task Constraints
*   Strict adherence to `SF-architecture.md` and `SF-roadmap.md`.
*   Zero functional application code, IaC, or database schemas may be written prior to the validation of this sub-roadmap.
*   Loose types (`any` in TS, `interface{}` in Go) are blocked.
*   All errors must be typed and mapped to `PlatformException`.

## Step-by-Step Implementation Tasks

### 1. Infrastructure-as-Code (Terraform)
*   **Target File:** `/build/terraform/main.tf` (or appropriate `.tf` structure)
*   **Action:** Write declarative Terraform configurations initializing:
    *   An `aws_eks_cluster` (name: `scriptureforge-production-cluster`) configured for private subnet access.
    *   An `aws_rds_cluster` (engine: `postgres`, version: `17.2`, name: `scriptureforge-core-postgres-cluster`) utilizing explicit static encryption keys (`storage_encrypted = true`).
    *   Ensure deletion protection is active (`deletion_protection = true`).

### 2. Database Extensions Migration
*   **Target File:** `/migrations/000001_init_extensions.up.sql`
*   **Action:** Create SQL migration steps to initialize necessary PostgreSQL extensions natively:
    *   Enable the `uuid-ossp` extension for secure ID generation.
    *   Enable the `vector` extension (pgvector) for semantic AI matching capabilities.

### 3. Core Relational Schema & Indices Generation
*   **Target File:** `/migrations/000002_core_schema.up.sql`
*   **Action:** Write accurate DDL table generation scripts establishing foundational multi-tenant data boundaries:
    *   `organizations` table.
    *   `users` table (incorporating tenant isolation).
    *   `scripture_texts` table.
    *   Apply specialized indexing, specifically constructing HNSW vector-cosine optimization models across target column paths for the `scripture_texts` data repository, alongside standard tracking indices.

### 4. Application Entrypoint & Connection Pooling
*   **Target File:** `/cmd/platform-engine/main.go`
*   **Action:** Construct the structural layout of the main Go monolithic service entry point:
    *   Implement environment variable parser.
    *   Initialize thread-safe connection pooling for PostgreSQL.
    *   Initialize thread-safe connection pooling for Redis.
    *   Ensure normal shutdown processes complete cleanly upon receiving standard OS termination signals.

### 5. Integration Testing Layout
*   **Target File:** `/tests/integration/db_ping_test.go`
*   **Action:** Implement an integration test layout explicitly detailing:
    *   Verification of relational database pool connectivity and durability.
    *   Validation of row-level multi-tenant isolation (RLS).
    *   Verification of rollback behavior execution under standard constraint faults.
    *   Validation of index usage maps.

## Acceptance Criteria
*   The localized multi-tenant environment completes initialization using isolated container structures, processing full relational migrations cleanly.
*   The Go initialization block establishes an active pool connection to PostgreSQL and Redis.
*   Public ingress access vectors are entirely deactivated inside relational database setups.
*   Database storage partitions enforce encryption parameters.
