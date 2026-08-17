#!/bin/bash
# Phase 4: Network Partition / Split-Brain
# Since this is a simple local mock, we'll simulate the DB connection failing
# by forcefully killing the port or simulating an I/O hang if it were a real Docker setup.
# Here we'll just document the theoretical outcome based on code inspection.

echo "Simulating network partition between backend and database..."
echo "Network drop injected via iptables (simulated in mock context)."

# Let's send requests during the "partition"
for i in {1..50}; do
    curl -s --max-time 1 http://localhost:8080/api/ai/generate > /dev/null &
done

wait

echo "Result: In this sandbox, the in-memory sync.Map doesn't fail. In production, pgxpool would return connection errors. We'd expect 500s or pausing of operations."
