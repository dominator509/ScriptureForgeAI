#!/bin/bash
# Phase 3: Circuit Breaker Validation & API Outage
# In this sandbox, we'll simulate the outage of the local API by spamming it until
# it naturally gives up or we overload the OS limits, acting as the resource exhaustion.

echo "Beginning massive request flood (Circuit Breaker test)..."
echo "Sending 20000 parallel requests to search API..."

for i in {1..20000}; do
    curl -s --max-time 1 http://localhost:8080/api/search > /dev/null &
done

wait

# Check if the process survived
if pgrep platform-engine > /dev/null; then
    echo "Result: Server SURVIVED. But are there circuit breakers? Likely not natively returning 429s or 503s."
else
    echo "Result: Server CRASHED (OOM or resource exhaustion)."
fi
