param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$legacyPath = Join-Path $root '.pgdata'
$pgBin = 'D:\PostgreSQL\bin'
$statusPath = Join-Path $root '.tools\postgres-service-admin-status.json'

function Write-State([string]$Stage, [string]$Message) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $statusPath) | Out-Null
    @{ stage = $Stage; message = $Message; updated_at = (Get-Date).ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
}

function Assert-LegacyPath {
    $expected = [IO.Path]::GetFullPath((Join-Path $root '.pgdata'))
    if (Test-Path -LiteralPath $legacyPath) {
        $resolved = (Resolve-Path -LiteralPath $legacyPath).Path
        if (-not $resolved.Equals($expected, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Parent $resolved) -ne $root) { throw 'Test cluster path is outside the project root.' }
        $links = @(Get-Item -LiteralPath $resolved -Force) + @(Get-ChildItem -LiteralPath $resolved -Force -Recurse)
        if ($links | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
            throw 'Refusing recursive removal: test cluster contains a junction or symbolic link.'
        }
    }
}

function Get-LegacyMain {
    $pidFile = Join-Path $legacyPath 'postmaster.pid'
    if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
    $idText = Get-Content -LiteralPath $pidFile -TotalCount 1
    [int]$legacyMainId = 0
    if (-not [int]::TryParse($idText, [ref]$legacyMainId) -or $legacyMainId -le 0) { throw 'Invalid test cluster PID file.' }
    $main = Get-CimInstance Win32_Process -Filter "ProcessId=$legacyMainId"
    if (-not $main) { return $null }
    $dataArg = '(?i)(?:^|\s)-D\s+(?:"' + [regex]::Escape($legacyPath) + '"|' + [regex]::Escape($legacyPath) + ')(?=\s|$)'
    if ($main.ExecutablePath -ne (Join-Path $pgBin 'postgres.exe') -or $main.CommandLine -notmatch $dataArg) {
        throw 'PID does not belong to the project test cluster; refusing to stop it.'
    }
    return $main
}

try {
    Assert-LegacyPath
    if ($ValidateOnly) {
        $main = Get-LegacyMain
        [pscustomobject]@{ service = 'postgresql-x64-18'; port = 5432; remove_path = $legacyPath; legacy_main_pid = $main.ProcessId }
        exit 0
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Windows administrator rights are required.' }

    Write-State 'starting_service' 'Starting the existing Windows service on port 5432.'
    $service = Get-Service -Name 'postgresql-x64-18'
    if ($service.Status -ne 'Running') { Start-Service -Name $service.Name }
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Set-Service -Name $service.Name -StartupType Automatic
    & (Join-Path $pgBin 'pg_isready.exe') -h 127.0.0.1 -p 5432 -t 3
    if ($LASTEXITCODE -ne 0) { throw 'The Windows service is not accepting connections on 5432. Test cluster retained.' }

    Write-State 'removing_test_cluster' 'Removing only the project .pgdata test cluster and its test databases.'
    $main = Get-LegacyMain
    if ($main) {
        $stopLog = Join-Path $root '.tools\postgres-test-stop.log'
        $stopErr = Join-Path $root '.tools\postgres-test-stop.err.log'
        $stopper = Start-Process -FilePath (Join-Path $pgBin 'pg_ctl.exe') -ArgumentList @('-D', ('"' + $legacyPath + '"'), '-m', 'fast', '-w', '-t', '10', 'stop') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stopLog -RedirectStandardError $stopErr
        if (-not $stopper.WaitForExit(15000)) { $stopper.Kill(); $stopper.WaitForExit() }
        $main = Get-LegacyMain
        if ($main) {
            # A clean stop may fail because of the previously recorded Windows
            # signal permissions. The user authorized removal of this test
            # cluster. Only its verified process tree may be terminated.
            $all = @(Get-CimInstance Win32_Process -Filter "Name='postgres.exe'")
            $owned = @($main)
            do {
                $parents = @($owned | ForEach-Object { $_.ProcessId })
                $new = @($all | Where-Object { $_.ParentProcessId -in $parents -and $_.ProcessId -notin $parents })
                $owned += $new
            } while ($new.Count -gt 0)
            foreach ($record in $owned) {
                $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.ProcessId)"
                if ($current -and $current.CreationDate -eq $record.CreationDate -and $current.ExecutablePath -eq (Join-Path $pgBin 'postgres.exe')) {
                    Stop-Process -Id $current.ProcessId -Force -ErrorAction SilentlyContinue
                }
            }
            foreach ($record in $owned) {
                $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.ProcessId)"
                if ($current -and $current.CreationDate -eq $record.CreationDate) {
                    throw 'A test cluster process could not be stopped; data directory retained.'
                }
            }
            if (Get-LegacyMain) { throw 'Test cluster process is still running; data directory retained.' }
        }
    }
    Assert-LegacyPath
    if (Test-Path -LiteralPath $legacyPath) { Remove-Item -LiteralPath $legacyPath -Recurse -Force }
    Write-State 'complete' 'Windows service running on 5432; project test cluster removed.'
    Write-Host 'PostgreSQL Windows service is running. Project test cluster removed.' -ForegroundColor Green
    exit 0
} catch {
    Write-State 'error' $_.Exception.Message
    Write-Error $_.Exception.Message
    exit 1
}
