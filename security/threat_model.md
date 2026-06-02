# Phase 1: Reconnaissance, Threat Modeling, and Secrets

## Attack Surface Mapping
* **External Network Boundaries:** REST API (port 8080), Secure WebSocket (wss://), gRPC interface (port 50051).
* **Identity perimeters:** JWT Bearer tokens mapped via Authorization headers or 'ticket' query strings.
* **Data in transit:** Protected exclusively via TLS/SSL termination at the AWS Application Load Balancer.
* **Data at rest:** Encrypted utilizing PostgreSQL native storage encryption and AWS KMS.

## STRIDE Threat Analysis
| Threat | Target | Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | JWT Identity Claims | Validated cryptographic signatures (HMAC-SHA256) inside `auth.RBACMiddleware`. |
| **Tampering** | API Payloads / WebSocket streams | Requests rejected if payload fails strict unmarshaling schemas. |
| **Repudiation** | Access Logs | System logging implemented across all endpoints via STDOUT aggregation. |
| **Information Disclosure** | Local Journal Entries | Zero-knowledge client-side encryption (AES-256-GCM via PBKDF2 isolation keys). |
| **Denial of Service** | WebSocket concurrent connections | Redis Lua scripts enforce atomic connection state management. |
| **Elevation of Privilege** | Tenant isolation boundaries | PostgreSQL Row Level Security (RLS) policies prevent cross-tenant queries. |

## Secrets Scanning Report
* **Findings:** Two hardcoded connection strings discovered during automated scan.
  * `services/scripture-engine/src/main.rs`: `postgres://forge_admin_root:testpassword@localhost/scriptureforge_prod`
  * `tests/integration/db_ping_test.go`: `postgres://forge_admin_root:testpassword@localhost/scriptureforge_prod`
* **Resolution:** Hardcoded test credentials have been purged and entirely replaced by secure environment variable injection parsing logic.
