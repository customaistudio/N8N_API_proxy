#!/usr/bin/env bash
set -euo pipefail

# Pulls secrets from macOS Keychain so they never touch a config file.
# One-time setup:
#   security add-generic-password -a n8n -s n8n-api-key -w "<your-n8n-api-key>"
#
# Replace N8N_BASE_URL with your instance URL.

export N8N_API_KEY="$(security find-generic-password -s n8n-api-key -w)"
export N8N_BASE_URL="${N8N_BASE_URL:?Error: N8N_BASE_URL not set. Export it or set in .env}"

exec node "$(dirname "$0")/index.js"
