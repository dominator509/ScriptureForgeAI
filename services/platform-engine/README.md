# API Container Definition

This directory contains only the production API Dockerfile. The API source is
the repository-root `cmd/platform-engine` package and must be built with the
repository root as its Docker build context.

The former nested in-memory mock service and WAL are intentionally removed so
they cannot be built or mistaken for the PostgreSQL/Redis-backed runtime.
