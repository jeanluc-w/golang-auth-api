#!/usr/bin/env bash

set -e

echo "Setting up Edibubble backend"

# Check required tools
REQUIRED_TOOLS=("go" "sqlc" "migrate" "psql" "redis-cli")
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" &> /dev/null; then
    echo "$tool is not installed. Please install it first."
    exit 1
  fi
done

# Load environment variables
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
  echo "Loaded environment from .env"
else
  echo "No .env file found. Create one referencing the '.copy.env' file before continuing."
  exit 1
fi

# Run sqlc code generation
echo "Generating SQLC models"
sqlc generate

# Run DB migrations
echo "Running database migrations"
migrate -path db/mi

echo "Completed Edibubble backend setup. Execute 'go run cmd/server' to start the server locally."