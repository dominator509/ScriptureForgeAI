# Historical Disaster-Recovery Emulation Report

**Status:** Historical mock-sandbox documentation, not production evidence
**Date:** 2026-05-20

This report documented an earlier in-memory `platform-engine` experiment that
replayed a local WAL file. That runtime was not the current PostgreSQL/Redis
application and its results must not be used to claim data durability,
rollback readiness, RPO, or RTO.

The current repository uses PostgreSQL, Redis, and the Terraform/RDS recovery
boundary. `scripts/disaster_recovery/backup.sh` now creates a checksummed
PostgreSQL custom-format archive, and `restore.sh` restores only to an
explicitly supplied isolated target after two confirmation variables are set.
Those helpers are operational tooling, not proof of a staging backup/restore
drill.

Authoritative production recovery evidence remains external and must include a
real encrypted snapshot, isolated restore, restored-database smoke, measured
RPO/RTO, exact release linkage, and the `DR-BACKUP-001`/`DR-ROLLBACK-001`
artifacts required by `tools/resilienceprobe` and the staging evidence
manifest.
