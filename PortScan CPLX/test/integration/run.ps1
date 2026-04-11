Param()
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
Write-Output "Building and starting test services..."
docker compose up -d --build
Start-Sleep -Seconds 3
$bin = Join-Path $here "..\..\webscan.exe"
if (-Not (Test-Path $bin)) {
  $bin = Join-Path $here "..\..\webscan"
}
if (Test-Path $bin) {
  & $bin scan -t 127.0.0.1 -p 8080 --timeout 3 --threads 10 --json > http.json
  & $bin scan -t 127.0.0.1 -p 8443 --timeout 3 --threads 10 --json > https.json
  & $bin scan -t 127.0.0.1 -p 8081 --timeout 3 --threads 10 --json > waf.json
  Write-Output "Outputs saved: http.json https.json waf.json"
} else {
  Write-Output "webscan binary not found. Build it first (from project root):"
  Write-Output "  go build -o webscan.exe ."
}
Write-Output "Tearing down services..."
docker compose down
