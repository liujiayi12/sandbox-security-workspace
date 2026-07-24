$ErrorActionPreference = "Stop"
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
Set-Location (Join-Path $PSScriptRoot "clawguard-main\web")
npm.cmd run dev:api
