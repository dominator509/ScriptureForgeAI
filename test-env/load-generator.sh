#!/bin/bash
# Generate high workload for Phase 1

echo "Generating load..."
for i in {1..200}; do
    curl -s http://localhost:8080/api/ai/generate > /dev/null &
    curl -s http://localhost:8080/api/zoom/active > /dev/null &
    curl -s http://localhost:8080/api/search > /dev/null &
done

wait
echo "Load generation complete."

HASH=$(curl -s http://localhost:8080/api/state)
echo "PRE_DISASTER_STATE_HASH: $HASH"
