#!/bin/bash
# Phase 2: Kill the platform engine hard mid-flight

echo "Starting massive load to simulate mid-flight transactions..."
for i in {1..500}; do
    curl -s http://localhost:8080/api/ai/generate > /dev/null &
    curl -s http://localhost:8080/api/zoom/active > /dev/null &
    curl -s http://localhost:8080/api/search > /dev/null &
done

sleep 0.1 # Wait just a fraction so it's processing

echo "Injecting kill -9 on platform-engine..."
PID=$(pgrep platform-engine)
if [ ! -z "$PID" ]; then
    kill -9 $PID
    echo "Killed PID $PID"
else
    echo "Process not found!"
fi

echo "Transactions dropped due to hard crash (system has no restart policy configured natively outside K8s in this sandbox)."

wait
echo "Done."
