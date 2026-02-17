#!/usr/bin/env bash
set -e

IMAGE_NAME="ai-security-triage"

echo "Building Docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

echo "Running triage..."
docker run --rm -v "$(pwd):/app" "$IMAGE_NAME"

echo ""
echo "Done. Check output/results.csv"
