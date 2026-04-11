# Integration test harness

This folder contains a small Docker Compose-based integration testbed for `webscan`.

Services
- `http` — an `nginx` container serving a simple static page on port `8080`.
- `https` — an `nginx` container with a self-signed certificate on port `8443`.
- `waf` — a tiny Python HTTP server that returns a 403 and WAF-like headers on port `8081`.

Quick start

Requirements: Docker and Docker Compose.

From the project root run:

```bash
cd test/integration
docker compose up -d --build
# then (on Linux/macOS)
./run.sh
# or on Windows PowerShell
./run.ps1
```

The run scripts will attempt to run `webscan` from the project root (`./webscan` or `./webscan.exe`) and save JSON outputs (`http.json`, `https.json`, `waf.json`).

Notes
- The HTTPS service uses a self-signed certificate so the probe should tolerate that (the scanner is configured to skip TLS verification for the probe).
- You can inspect service logs with `docker compose logs -f`.
