param(
    [string]$Path,
    [ValidateSet('all','devices','links','pending')][string]$View = 'all',
    [ValidateRange(1,10000)][int]$Limit = 20
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
if (-not $Path) { $Path = Join-Path $root 'outputs\topology-latest.json' }
if (-not (Test-Path -LiteralPath $Path)) { throw '未找到拓扑文件，请先执行 scripts/scan.ps1。' }
$topology = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
function Safe-Text($Value) { return ([string]$Value -replace '[\x00-\x1f\x7f-\x9f]', ' ') }
function Kind-Label($Kind) { switch($Kind){'router'{'路由器'} 'wireless_controller'{'无线 AC'} default{'交换机'}} }
function Chassis-MAC($Keys) {
    foreach ($key in $Keys) {
        if ([string]$key -match '^lldp:[47]:([0-9a-f]{12})$') { return (($Matches[1] -split '(.{2})' | Where-Object { $_ }) -join ':') }
    }
    return '-'
}
$names = @{}
foreach ($d in $topology.devices) { $label=$d.sys_name; if($d.inventory_name){$label=$d.inventory_name}; $names[[string]$d.id] = Safe-Text $label }
Write-Host ("轮次 {0}  状态 {1}  已确认设备 {2}  链路 {3}  待识别端点 {4}" -f $topology.latest_scan_id, $topology.latest_scan_status, $topology.devices.Count, $topology.links.Count, $topology.pending_nodes.Count)
if($topology.device_counts){$c=$topology.device_counts;Write-Host ("台账范围 {0}；本轮采集 {1}；仅有历史记录 {2}；尚未确认 {3}。设备按 chassis 去重，堆叠按一个逻辑节点统计。" -f $c.inventory,$c.collected_this_scan,$c.historical_only,$c.unconfirmed)}
if($topology.device_counts){$c=$topology.device_counts;Write-Host ("交换机 {0}；路由器 {1}；无线 AC {2}；另有待核验路由器 {3} / 无线 AC {4}。" -f $c.switches,$c.routers,$c.wireless_controllers,$c.pending_routers,$c.pending_wireless_controllers)}
if ($View -in @('all','devices')) {
    Write-Host "`n已确认网络设备（层级 0 为配置的扫描起点）"
    $topology.devices | ForEach-Object {
        $depth = '-'; if ($null -ne $_.discovery_depth) { $depth = $_.discovery_depth }
        $label=$_.sys_name;if($_.inventory_name){$label=$_.inventory_name}
        [pscustomobject]@{ ID=$_.id; 类型=(Kind-Label $_.device_kind); 层级=$depth; 区域=$_.area; 设备=(Safe-Text $label); 采集地址=($_.access_addresses -join ','); ChassisMAC=(Chassis-MAC $_.identity_keys) }
    } | Format-Table -AutoSize -Wrap | Out-Host
}
if ($View -in @('all','links')) {
    Write-Host '已确认链路（端口列为设备通告描述）'
    $topology.links | ForEach-Object {
        $confidence = '单向'; if ($_.confidence -eq 'bidirectional') { $confidence = '双向' }
        [pscustomobject]@{ ID=$_.id; 本端=$names[[string]$_.device_a_id]; 本端口描述=(Safe-Text $_.port_a_name); 对端=$names[[string]$_.device_b_id]; 对端口描述=(Safe-Text $_.port_b_name); 确认=$confidence; 状态=$_.discovery_state }
    } | Format-Table -AutoSize -Wrap | Out-Host
}
if ($View -in @('all','pending')) {
    Write-Host ("待识别端点（共 {0} 个，最多显示 {1} 个；不计为已确认交换机）" -f $topology.pending_nodes.Count, $Limit)
    $topology.pending_nodes | Sort-Object @{Expression={ -not [bool]$_.system_name }},system_name,key | Select-Object -First $Limit | ForEach-Object {
        $node = $_; $sourceNames = @($topology.pending_links | Where-Object remote_key -eq $node.key | ForEach-Object { $names[[string]$_.local_device_id] } | Sort-Object -Unique)
        $name = Safe-Text $node.system_name; if (-not $name) { $name = '(未通告名称)' }
        $state = '待识别/未采集'; if ($node.status -eq 'identity_conflict') { $state = '身份冲突' }
        [pscustomobject]@{ 邻居=$name; ChassisMAC=(Chassis-MAC @($node.key)); 发现来源=($sourceNames -join ','); 状态=$state }
    } | Format-Table -AutoSize -Wrap | Out-Host
    if($topology.pending_nodes.Count){Write-Host '继续采集需要该设备的 SNMP 访问地址；身份和链路匹配仍使用 chassis/port。'}
    if ($topology.pending_nodes.Count -gt $Limit) { Write-Host '查看全部：pwsh -NoProfile -File .\scripts\show-topology.ps1 -View pending -Limit 1000' }
}
if($topology.inventory_devices) {
    $unconfirmed=@($topology.inventory_devices|Where-Object status -ne 'collected')
    if($unconfirmed.Count){Write-Host '本轮未确认采集的台账设备：';$unconfirmed|Select-Object area,name,address,status|Format-Table -AutoSize|Out-Host}
}
if($View -in @('all','pending') -and $topology.neighbor_candidates.Count){
    Write-Host ('未确认邻居记录：'+$topology.neighbor_candidates.Count+' 条（可能包括范围外设备，不计入已确认设备数）')
    $topology.neighbor_candidates|Select-Object -First $Limit|ForEach-Object {$kind='待识别';if($_.device_kind){$kind=Kind-Label $_.device_kind};[pscustomobject]@{邻居=(Safe-Text $_.system_name);类型=$kind;型号=(Safe-Text $_.model);Chassis=$_.key;发现来源=($_.observed_by-join ',')}}|Format-Table -AutoSize -Wrap|Out-Host
}
