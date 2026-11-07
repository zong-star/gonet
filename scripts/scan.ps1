param(
    [string]$ConfigPath,
    [string]$OutputDirectory,
    [string]$ScopePath,
    [switch]$Quiet,
    [switch]$ExportOnly
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $root 'config.yaml' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'outputs' }
if (-not $ScopePath) { $ScopePath = Join-Path $root 'config\scan-scope.json' }
. (Join-Path $PSScriptRoot 'topology-scope.ps1')
$scanCode = $null
$exitCode = 2
$logPath = $null
$statusPath = $null
$summaryPath = $null

function Write-RunStatus($Value) {
    $tempPath = $statusPath + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($tempPath, ($Value | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($tempPath, $statusPath, $true)
    } finally {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath }
    }
}

Push-Location $root
try {
    $ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
    # Task Scheduler may inherit old environment values. Resolve this config's
    # env references from the current user's saved variables on every run.
    $configText = [IO.File]::ReadAllText($ConfigPath)
    $scope = Read-ScanScope $ScopePath
    if($scope.mode -ne 'lldp'){Assert-ScanScope $scope $configText}
    $references = [regex]::Matches($configText, '(?m)^\s*[a-z_]+_env:\s*[''"]?([A-Za-z_][A-Za-z0-9_]*)')
    foreach ($match in $references) {
        $name = $match.Groups[1].Value
        $value = [Environment]::GetEnvironmentVariable($name, 'User')
        if ($value) { [Environment]::SetEnvironmentVariable($name, $value, 'Process') }
    }
    $binary = @((Join-Path $root 'gonet.exe'), (Join-Path $root '.tools\gonet-service.exe')) |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $binary) { throw 'GoNet binary is missing.' }
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $stamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6)
    $logPath = Join-Path $OutputDirectory ('scan-' + $stamp + '.log')
    $statusPath = Join-Path $OutputDirectory 'latest-status.json'
    $topologyPath = Join-Path $OutputDirectory 'topology-latest.json'
    if (-not $ExportOnly) {
        $summaryPath = Join-Path $OutputDirectory ('scan-' + $stamp + '.json')
        & $binary scan --config $ConfigPath --output $summaryPath 2>> $logPath
        $scanCode = $LASTEXITCODE
        if ($scanCode -eq 5) {
            Write-RunStatus @{ status = 'skipped_locked'; scan_exit_code = 5; updated_at = (Get-Date).ToString('o'); log = $logPath }
            Write-Host '已有扫描正在运行，本次跳过。'
            exit 0
        }
        if ($scanCode -notin @(0, 3)) { $exitCode = $scanCode; throw 'Scan did not commit usable results.' }
    }
    $rawTopologyPath = Join-Path $OutputDirectory ('topology-export-' + $stamp + '.json')
    $exportArguments=@('topology','export','--config',$ConfigPath,'--state','all','--output',$rawTopologyPath,'--overwrite')
    if($scope.mode -eq 'lldp'){$exportArguments+=@('--scope',$ScopePath)}
    & $binary @exportArguments 2>> $logPath
    if ($LASTEXITCODE -ne 0) { $exitCode = $LASTEXITCODE; throw 'Topology export failed.' }
    $topology = Get-Content -Raw -LiteralPath $rawTopologyPath | ConvertFrom-Json
    if($scope.mode -ne 'lldp'){$topology = Select-TopologyScope $topology $scope}
    $tempTopologyPath=$topologyPath+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::WriteAllText($tempTopologyPath,($topology | ConvertTo-Json -Depth 25),[Text.UTF8Encoding]::new($false))
        [IO.File]::Move($tempTopologyPath,$topologyPath,$true)
    } finally {if(Test-Path -LiteralPath $tempTopologyPath){Remove-Item -LiteralPath $tempTopologyPath}}
    & (Join-Path $PSScriptRoot 'draw-topology.ps1') -Path $topologyPath -OutputDirectory $OutputDirectory
    & (Join-Path $PSScriptRoot 'draw-core-topology.ps1') -Path $topologyPath -OutputDirectory (Join-Path $OutputDirectory 'core')
    Write-RunStatus @{
        status = $topology.latest_scan_status; scan_id = $topology.latest_scan_id
        scan_exit_code = $scanCode; export_only = [bool]$ExportOnly
        devices = $topology.devices.Count; links = $topology.links.Count
        pending_nodes = $topology.pending_nodes.Count; pending_links = $topology.pending_links.Count
        unconfirmed_neighbors = $topology.neighbor_candidates.Count
        device_counts = $topology.device_counts
        updated_at = (Get-Date).ToString('o'); topology = $topologyPath; summary = $summaryPath; log = $logPath
        diagram = (Join-Path $OutputDirectory 'topology-latest.svg')
        devices_csv = (Join-Path $OutputDirectory 'topology-devices.csv')
        links_csv = (Join-Path $OutputDirectory 'topology-links.csv')
        neighbor_candidates_csv = (Join-Path $OutputDirectory 'topology-neighbor-candidates.csv')
    }
    Write-Host ("扫描轮次 {0}，状态 {1}；{2} 台网络设备，{3} 条链路。" -f $topology.latest_scan_id, $topology.latest_scan_status, $topology.devices.Count, $topology.links.Count)
    Write-Host ("拓扑文件：{0}" -f $topologyPath)
    Write-Host ("运行状态：{0}" -f $statusPath)
    if (-not $Quiet) { & (Join-Path $PSScriptRoot 'show-topology.ps1') -Path $topologyPath -Limit 12 }
    # A partial committed scan is a completed scheduled job. Preserve the
    # original CLI exit code/status in latest-status.json rather than retrying.
    exit 0
} catch {
    if ($statusPath) {
        Write-RunStatus @{ status = 'failed'; scan_exit_code = $scanCode; job_exit_code = $exitCode; updated_at = (Get-Date).ToString('o'); log = $logPath }
    }
    Write-Host '扫描或导出未完成，请检查配置、环境变量及 outputs 中的日志。' -ForegroundColor Red
    exit $exitCode
} finally {
    # Bound generated summary/log/export batches after publishing latest files.
    if ($binary -and $logPath -and (Test-Path -LiteralPath $OutputDirectory)) {
        & $binary history prune --config $ConfigPath --output-dir $OutputDirectory --files-only 1>$null 2>>$logPath
        if ($LASTEXITCODE -ne 0) { Write-Warning '历史输出清理未完成，当前拓扑已保留。' }
    }
    Pop-Location
}
