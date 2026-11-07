function Read-ScanScope([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $scope=Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($scope.version -ne 1) { throw '扫描范围清单无效。' }
    if ($scope.mode -eq 'lldp') {
        if (-not @($scope.settings.seeds).Count -or -not @($scope.settings.allowed_cidrs).Count) { throw 'LLDP 发现范围无起点或允许范围。' }
    } elseif (-not @($scope.rows | Where-Object included).Count) { throw '扫描范围清单无效。' }
    return $scope
}

function Assert-ScanScope($Scope,[string]$ConfigText) {
    if (-not $Scope) {return}
    $allowed=@{}; foreach($r in $Scope.rows | Where-Object included) {$allowed[[string]$r.address]=$true}
    # Inventory-scoped config uses explicit flow lists. Fail closed if its
    # layout or scope changes, before the Go process sends network traffic.
    foreach($field in @('seeds','management_cidrs')) {
        $match=[regex]::Match($ConfigText,'(?m)^  '+$field+':\s*\[([^\]\r\n]+)\]\s*$')
        if(-not $match.Success){throw ('范围模式要求 '+$field+' 使用明确地址列表。')}
        foreach($value in $match.Groups[1].Value -split ',') {
            $address=$value.Trim().Trim('"',"'")
            if($field -eq 'management_cidrs') {
                if(-not $address.EndsWith('/32')) {throw '范围模式只允许 /32 精确地址。'}
                $address=$address.Substring(0,$address.Length-3)
            }
            if(-not $allowed.ContainsKey($address)){throw ('扫描地址不在台账允许清单：'+$address)}
        }
    }
}

function Select-TopologyScope($Topology,$Scope) {
    if(-not $Scope){return $Topology}
    $byIdentity=@{}; $byAddress=@{}
    foreach($r in $Scope.rows | Where-Object included) {
        $byAddress[[string]$r.address]=$r
        foreach($key in $r.identity_keys) {
            if($byIdentity.ContainsKey($key) -and $byIdentity[$key].row -ne $r.row){throw '台账存在重复 chassis，拒绝按地址拆分设备。'}
            $byIdentity[$key]=$r
        }
    }
    $kept=@{}; $foundRows=@{}
    $devices=@(foreach($d in $Topology.devices) {
        $row=$null
        foreach($key in $d.identity_keys){if($byIdentity.ContainsKey($key)){$row=$byIdentity[$key];break}}
        # A roster identity is pinned by direct chassis observation. A reused
        # management address cannot make a different device enter this view.
        if(-not $row){continue}
        $kept[[string]$d.id]=$true; $foundRows[[string]$row.row]=$d
        $d | Add-Member inventory_name $row.name -Force
        $d | Add-Member area $row.area -Force
        $d | Add-Member inventory_row $row.row -Force
        $d
    })
    $allPending=@($Topology.pending_links)
    $sourceNames=@{};foreach($d in $Topology.devices){$label=$d.sys_name;if($d.inventory_name){$label=$d.inventory_name};$sourceNames[[string]$d.id]=$label}
    $candidates=@(foreach($n in $Topology.pending_nodes){
        if($byIdentity.ContainsKey([string]$n.key)){continue}
        $observations=@($allPending|Where-Object {$_.remote_key-eq $n.key -and $kept.ContainsKey([string]$_.local_device_id)})
        if(-not $observations.Count){continue}
        [pscustomobject]@{key=$n.key;system_name=$n.system_name;chassis_subtype=$n.chassis.subtype;chassis_hex=$n.chassis.raw_hex;observed_by=@($observations|ForEach-Object {$sourceNames[[string]$_.local_device_id]}|Sort-Object -Unique);status='unconfirmed_neighbor';observed_at=($observations|Sort-Object observed_at -Descending|Select-Object -First 1).observed_at}
    })
    $Topology|Add-Member neighbor_candidates $candidates -Force
    $Topology.devices=$devices
    $Topology.links=@($Topology.links|Where-Object {$kept.ContainsKey([string]$_.device_a_id) -and $kept.ContainsKey([string]$_.device_b_id)})
    $Topology.pending_links=@($allPending|Where-Object {$kept.ContainsKey([string]$_.local_device_id) -and $kept.ContainsKey([string]$_.remote_device_id)})
    $Topology.pending_nodes=@()
    $Topology | Add-Member scope ([pscustomobject]@{included=$Scope.included_count;excluded=$Scope.excluded_count;hidden_observations=($allPending.Count-$Topology.pending_links.Count);unconfirmed_neighbors=$candidates.Count;source=$Scope.source}) -Force
    $Topology | Add-Member inventory_devices @(foreach($r in $Scope.rows|Where-Object included) {
        $d=$foundRows[[string]$r.row]
        [pscustomobject]@{row=$r.row;area=$r.area;name=$r.name;address=$r.address;model=$r.model;device_id=$d.id;observed_this_scan=($null -ne $d.discovery_depth);status=$(if($d){if($null -ne $d.discovery_depth){'collected'}else{'historical'}}else{'unconfirmed'})}
    }) -Force
    $Topology|Add-Member device_counts ([pscustomobject]@{inventory=$Scope.included_count;confirmed=$devices.Count;collected_this_scan=@($Topology.inventory_devices|Where-Object status -eq 'collected').Count;historical_only=@($Topology.inventory_devices|Where-Object status -eq 'historical').Count;unconfirmed=@($Topology.inventory_devices|Where-Object status -eq 'unconfirmed').Count;unconfirmed_neighbor_records=$candidates.Count}) -Force
    $Topology.coverage_gap=($Topology.latest_scan_status -ne 'completed' -or $Topology.pending_links.Count -gt 0 -or @($Topology.links|Where-Object { -not $_.fresh }).Count -gt 0)
    return $Topology
}
