#!/bin/bash
# A mock environment that simulates our backend and DB for chaos testing.
# Since Docker limits are hit, we'll run simple native go processes.

export DB_USER="mock"
export DB_PASS="mock"
export DB_HOST="mock"
export DB_NAME="mock"
export REDIS_HOST="mock"
export REDIS_PORT="mock"
export JWT_SECRET_KEY="testing-secret-key-123"

echo "Mock environment started."
