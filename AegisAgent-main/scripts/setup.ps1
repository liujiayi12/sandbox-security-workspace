param(
    [switch]$BuildImages,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Warning "Docker was not found on PATH. Static scanning will work, but dynamic sandbox runs require Docker Desktop."
}

if (-not (Test-Path ".venv")) {
    & $Python -m venv .venv
}

& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt

if ($BuildImages) {
    powershell -ExecutionPolicy Bypass -File "docker\images\scripts\build.ps1"
}

Write-Host ""
Write-Host "AegisAgent setup complete."
Write-Host "Start the server with:"
Write-Host "  .\.venv\Scripts\python.exe -m agent_sandbox"
Write-Host "Then open http://127.0.0.1:8000"
