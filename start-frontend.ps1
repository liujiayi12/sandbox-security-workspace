$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "sandbox-console")
npm.cmd run dev
