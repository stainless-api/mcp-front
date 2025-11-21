#!/bin/bash
set -e

echo "Validating all config files in the repository..."
failed=0

# Check root level config files
for config in *.json; do
  if [[ -f "$config" ]]; then
    echo "Checking $config..."
    if ! ./cmd/mcp-front/mcp-front -validate -config "$config"; then
      failed=1
    fi
  fi
done

# Check integration test config files
for config in integration/config/*.json; do
  if [[ -f "$config" ]]; then
    echo "Checking $config..."
    if ! ./cmd/mcp-front/mcp-front -validate -config "$config"; then
      failed=1
    fi
  fi
done

if [[ $failed -eq 1 ]]; then
  echo "❌ Config validation failed for one or more files"
  exit 1
else
  echo "✅ All config files validated successfully"
fi
