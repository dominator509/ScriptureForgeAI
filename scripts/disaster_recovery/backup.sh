#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/.tmp/disaster-recovery}"
DATABASE_URL="${DATABASE_URL:-}"

if [[ -z "$DATABASE_URL" ]]; then
  echo "DATABASE_URL is required; no backup was created." >&2
  exit 2
fi
if ! command -v pg_dump >/dev/null 2>&1; then
  echo "pg_dump is required on PATH; no backup was created." >&2
  exit 2
fi
if ! command -v pg_restore >/dev/null 2>&1; then
  echo "pg_restore is required on PATH; no backup was created." >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "sha256sum or shasum is required on PATH; no backup was created." >&2
  exit 2
fi

mkdir -p -- "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot_name="scriptureforge-${timestamp}.dump"
snapshot_path="$BACKUP_DIR/$snapshot_name"

echo "Creating PostgreSQL custom-format backup: $snapshot_name"
pg_dump \
  --dbname="$DATABASE_URL" \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file="$snapshot_path"

if [[ ! -s "$snapshot_path" ]]; then
  echo "pg_dump produced an empty backup; refusing to publish it." >&2
  rm -f -- "$snapshot_path"
  exit 1
fi
pg_restore --list "$snapshot_path" >/dev/null

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$snapshot_path" > "$snapshot_path.sha256"
else
  shasum -a 256 "$snapshot_path" > "$snapshot_path.sha256"
fi
printf '%s\n' "$snapshot_name" > "$BACKUP_DIR/latest_snapshot.info"
printf 'format=postgres-custom\ncreated_at=%s\nsnapshot_file=%s\n' \
  "$timestamp" "$snapshot_name" > "$snapshot_path.meta"

echo "Backup created and checksum recorded in $BACKUP_DIR"
