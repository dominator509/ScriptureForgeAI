#!/bin/bash
# Mock backup script to save the current WAL state

echo "Starting automated disaster recovery snapshot..."

if [ ! -f "services/platform-engine/state_wal.log" ]; then
    echo "Error: WAL file not found. Nothing to backup."
else
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    SNAPSHOT_FILE="snapshot_${TIMESTAMP}.wal.bak"

    cp services/platform-engine/state_wal.log "scripts/disaster_recovery/${SNAPSHOT_FILE}"
    echo "Snapshot saved to scripts/disaster_recovery/${SNAPSHOT_FILE}"

    # Store the latest snapshot reference
    echo "$SNAPSHOT_FILE" > scripts/disaster_recovery/latest_snapshot.info

    # Let's also grab the hash representation for metadata
    HASH=$(curl -s http://localhost:8080/api/state)
    echo "State Hash: $HASH" >> "scripts/disaster_recovery/${SNAPSHOT_FILE}.meta"

    echo "Backup successful."
fi
