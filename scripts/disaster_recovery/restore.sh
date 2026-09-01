#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/.tmp/disaster-recovery}"
TARGET_DATABASE_URL="${TARGET_DATABASE_URL:-}"
SOURCE_DATABASE_URL="${DATABASE_URL:-}"

if [[ -z "$TARGET_DATABASE_URL" ]]; then
  echo "TARGET_DATABASE_URL is required; no restore was attempted." >&2
  exit 2
fi
if [[ -n "$SOURCE_DATABASE_URL" && "$TARGET_DATABASE_URL" == "$SOURCE_DATABASE_URL" ]]; then
  echo "TARGET_DATABASE_URL must differ from DATABASE_URL; restore into an isolated target." >&2
  exit 2
fi
if [[ "${CONFIRM_RESTORE:-}" != "YES" || "${ALLOW_DESTRUCTIVE_RESTORE:-}" != "YES" ]]; then
  echo "Set CONFIRM_RESTORE=YES and ALLOW_DESTRUCTIVE_RESTORE=YES; no restore was attempted." >&2
  exit 2
fi
if ! command -v pg_restore >/dev/null 2>&1; then
  echo "pg_restore is required on PATH; no restore was attempted." >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "sha256sum or shasum is required on PATH; no restore was attempted." >&2
  exit 2
fi

snapshot_name="${SNAPSHOT_FILE:-}"
if [[ -z "$snapshot_name" ]]; then
  if [[ ! -f "$BACKUP_DIR/latest_snapshot.info" ]]; then
    echo "No latest snapshot reference found; no restore was attempted." >&2
    exit 1
  fi
  snapshot_name="$(< "$BACKUP_DIR/latest_snapshot.info")"
fi

if [[ ! "$snapshot_name" =~ ^scriptureforge-[0-9]{8}T[0-9]{6}Z\.dump$ ]]; then
  echo "SNAPSHOT_FILE must name a backup created by backup.sh; no restore was attempted." >&2
  exit 2
fi

snapshot_path="$BACKUP_DIR/$snapshot_name"
checksum_path="$snapshot_path.sha256"
if [[ ! -f "$snapshot_path" || ! -f "$checksum_path" ]]; then
  echo "Snapshot or checksum is missing; no restore was attempted." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd -- "$BACKUP_DIR" && sha256sum --check "$(basename -- "$checksum_path")")
else
  (cd -- "$BACKUP_DIR" && shasum -a 256 --check "$(basename -- "$checksum_path")")
fi

echo "Restoring $snapshot_name into the explicitly supplied isolated target database."
pg_restore \
  --dbname="$TARGET_DATABASE_URL" \
  --clean \
  --if-exists \
  --exit-on-error \
  --no-owner \
  --no-privileges \
  "$snapshot_path"

echo "Restore completed; run the restored-database application smoke and RLS checks before promotion."
