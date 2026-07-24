$ErrorActionPreference = "Stop"
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
Set-Location (Join-Path $PSScriptRoot "AegisAgent-main")
.\.venv\Scripts\python.exe -m agent_sandbox --host 127.0.0.1 --port 8000
