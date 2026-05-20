#!/bin/bash

echo "Testing Study Plan Generation (Missing payload)..."
curl -s -X POST http://localhost:8080/api/v1/study-plans -H "Content-Type: application/json" -d '{}' > study_plan_err.json

echo -e "\nTesting Zoom Webhook (Missing Signature)..."
curl -s -X POST http://localhost:8080/api/v1/webhooks/zoom -H "Content-Type: application/json" -d '{"event":"meeting.started"}' > zoom_webhook_err.json

echo -e "\nOutput Analysis:"
echo "Study Plan Error Payload:"
cat study_plan_err.json | jq . || cat study_plan_err.json

echo -e "\n\nZoom Webhook Error Payload:"
cat zoom_webhook_err.json | jq . || cat zoom_webhook_err.json
