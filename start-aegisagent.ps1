$ErrorActionPreference = "Stop"
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
$env:AGENT_SANDBOX_IMAGE_MIRROR_PREFIXES = "docker.1ms.run,hub.rat.dev"
Write-Host "AegisAgent image mirrors: $env:AGENT_SANDBOX_IMAGE_MIRROR_PREFIXES"
Set-Location (Join-Path $PSScriptRoot "AegisAgent-main")
.\.venv\Scripts\python.exe -m agent_sandbox --host 127.0.0.1 --port 8000
