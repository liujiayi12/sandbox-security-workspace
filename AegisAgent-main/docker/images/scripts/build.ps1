param(
  [ValidateSet('python','node','go','rust','java','universal','all')]
  [string]$Name = 'all'
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')

$images = [ordered]@{
  python    = @{ Path = 'python';    Tag = 'aegisagent-python:3.12-bookworm' }
  node      = @{ Path = 'node';      Tag = 'aegisagent-node:22-bookworm' }
  go        = @{ Path = 'go';        Tag = 'aegisagent-go:1.24-bookworm' }
  rust      = @{ Path = 'rust';      Tag = 'aegisagent-rust:1-bookworm' }
  java      = @{ Path = 'java';      Tag = 'aegisagent-java:21-bookworm' }
  universal = @{ Path = 'universal'; Tag = 'aegisagent-universal:linux' }
}

$selected = if ($Name -eq 'all') { $images.Keys } else { @($Name) }

foreach ($key in $selected) {
  $item = $images[$key]
  $context = Join-Path $root $item.Path
  Write-Host "Building $($item.Tag) from $context"
  docker build -t $item.Tag $context
}
