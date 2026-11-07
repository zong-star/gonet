param([string]$Path,[string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
if(-not $Path){$Path=Join-Path $root 'outputs\topology-latest.json'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path (Split-Path -Parent $Path) 'core'}
$t=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
$core=@($t.devices|Where-Object {$_.identity_keys -contains 'manual:ts7914-core-stack-01'})
if($core.Count -ne 1){return}
$coreID=$core[0].id
$links=@($t.links|Where-Object {$_.device_a_id-eq $coreID -or $_.device_b_id-eq $coreID})
$ids=@{};$ids[[string]$coreID]=$true
foreach($l in $links){$ids[[string]$l.device_a_id]=$true;$ids[[string]$l.device_b_id]=$true}
$t.devices=@($t.devices|Where-Object {$ids.ContainsKey([string]$_.id)})
$t.links=$links
$t.inventory_devices=@($t.inventory_devices|Where-Object {$ids.ContainsKey([string]$_.device_id)})
$t.pending_nodes=@()
$t|Add-Member device_counts ([pscustomobject]@{inventory=$t.inventory_devices.Count;confirmed=$t.devices.Count;collected_this_scan=@($t.devices|Where-Object {$null-ne $_.discovery_depth}).Count;historical_only=@($t.devices|Where-Object {$null-eq $_.discovery_depth}).Count;unconfirmed=0;unconfirmed_neighbor_records=0}) -Force
$t|Add-Member neighbor_candidates @() -Force
$t.pending_links=@($t.pending_links|Where-Object {$ids.ContainsKey([string]$_.local_device_id)-and $ids.ContainsKey([string]$_.remote_device_id)})
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
$corePath=Join-Path $OutputDirectory 'topology-core.json'
[IO.File]::WriteAllText($corePath,($t|ConvertTo-Json -Depth 25),[Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot 'draw-topology.ps1') -Path $corePath -OutputDirectory $OutputDirectory -Title 'gonet · 核心上联' -Description '下方每台均直接连接核心，位置只为排版；双机堆叠为一个逻辑节点，双上联分别画线。完整下联见总图。' -CoreOverview
