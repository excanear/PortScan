#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Building and starting test services..."
docker compose up -d --build
echo "Waiting for services to become ready..."
sleep 3
echo "Running webscan against services..."
BIN="../../webscan"
if [ ! -x "$BIN" ]; then
  BIN="../../webscan.exe"
fi
if [ -x "$BIN" ]; then
  "$BIN" scan -t 127.0.0.1 -p 8080 --timeout 3 --threads 10 --json > http.json || true
  "$BIN" scan -t 127.0.0.1 -p 8443 --timeout 3 --threads 10 --json > https.json || true
  "$BIN" scan -t 127.0.0.1 -p 8081 --timeout 3 --threads 10 --json > waf.json || true
  echo "Outputs saved: http.json https.json waf.json"
else
  echo "webscan binary not found. Build it first (from project root):"
  echo "  go build -o webscan.exe ."
fi
echo "Tearing down services..."
docker compose down
