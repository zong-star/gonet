param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root '.tools\stability' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$outputPath = (Resolve-Path -LiteralPath $OutputDirectory).Path
$exe = Join-Path $outputPath 'discovery.test.exe'
$stdoutPath = Join-Path $outputPath 'test.log'
$stderrPath = Join-Path $outputPath 'test.err.log'
Push-Location $root
try {
    if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $root '.gocache' }
    go test -c -o $exe ./internal/discovery
    if ($LASTEXITCODE -ne 0) { throw 'Build stability test executable failed' }
    $process = Start-Process -FilePath $exe -ArgumentList @('-test.run=^TestT502200Devices$', '-test.v') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    [long]$peak = 0
    while (-not $process.HasExited) {
        $process.Refresh()
        if ($process.PeakWorkingSet64 -gt $peak) { $peak = $process.PeakWorkingSet64 }
        Start-Sleep -Milliseconds 10
    }
    $process.WaitForExit()
    Get-Content -LiteralPath $stdoutPath
    if ($process.ExitCode -ne 0) { Get-Content -LiteralPath $stderrPath; throw "Stability test exit $($process.ExitCode)" }
    if ($peak -eq 0 -or $peak -gt 256MB) { throw "Peak process working set out of budget: $peak bytes" }
    $result = [ordered]@{ test = 'TestT502200Devices'; peak_working_set_bytes = $peak; limit_bytes = 256MB; exit_code = $process.ExitCode }
    $result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputPath 'metrics.json') -Encoding utf8
    $result | ConvertTo-Json
} finally { Pop-Location }
