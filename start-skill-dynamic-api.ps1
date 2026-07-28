$ErrorActionPreference = "Stop"
$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;$env:PATH"
$env:AUTH_STORAGE = "file"
$env:DEFAULT_ADMIN_USERNAME = "admin"
$env:DEFAULT_ADMIN_PASSWORD = "Admin123456"
$env:DEFAULT_ADMIN_PHONE = "13800000000"
$env:PROVLOOM_DOCKER_CONFIG = Join-Path $PSScriptRoot "clawguard-main\runtime-cache\skill-dynamic\docker-config"
$env:PROVLOOM_REBUILD_SANDBOX_IMAGE = "0"
Set-Location (Join-Path $PSScriptRoot "clawguard-main\web")
npm.cmd run dev:api
