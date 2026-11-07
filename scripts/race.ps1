#!/usr/bin/env pwsh
# Runs the Go race gate using the workspace-local MinGW-w64 toolchain.
#
# One-time setup (network permitting):
#   1. Download a portable winlibs MinGW-w64 zip (x86_64-posix-seh-ucrt).
#      The environment's Schannel cannot fetch HTTPS, so use any tool that can
#      (for example a small Go downloader) rather than Invoke-WebRequest.
#   2. Extract it so that gcc.exe lives at .tools/mingw/mingw64/bin/gcc.exe.
#
# Usage: pwsh -File scripts/race.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$mingwBin = Join-Path $root '.tools\mingw\mingw64\bin'
$gcc = Join-Path $mingwBin 'gcc.exe'
if (-not (Test-Path $gcc)) {
    Write-Error "MinGW-w64 gcc not found at $gcc. See docs/acceptance/M3.md for setup."
}
$env:PATH = "$mingwBin;$env:PATH"
$env:CGO_ENABLED = '1'
$env:CC = $gcc
if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $root '.gocache' }
Push-Location $root
try {
    go test -race ./...
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
