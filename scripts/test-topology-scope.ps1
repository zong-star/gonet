$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'topology-scope.ps1')
$scope=[pscustomobject]@{version=1;included_count=1;excluded_count=1;source='synthetic';rows=@(
 [pscustomobject]@{included=$true;row=2;name='Allowed';area='Lab';address='192.0.2.1';identity_keys=@('lldp:4:020000000001')},
 [pscustomobject]@{included=$false;row=3;name='Excluded';area='Office';address='192.0.2.2';identity_keys=@('lldp:4:020000000002')}
)}
Assert-ScanScope $scope "  seeds: [192.0.2.1]`n  management_cidrs: [192.0.2.1/32]"
foreach($bad in @("  seeds: [192.0.2.2]`n  management_cidrs: [192.0.2.1/32]","  seeds: [192.0.2.1]`n  management_cidrs: [192.0.2.0/24]")){
 $rejected=$false;try{Assert-ScanScope $scope $bad}catch{$rejected=$true};if(-not $rejected){throw 'Out-of-scope config was accepted.'}
}
$topology=[pscustomobject]@{latest_scan_status='partial';coverage_gap=$true;devices=@(
 [pscustomobject]@{id=1;identity_keys=@('lldp:4:020000000001');discovery_depth=0},
 [pscustomobject]@{id=2;identity_keys=@('lldp:4:020000000002');access_addresses=@('192.0.2.1');discovery_depth=0}
);links=@([pscustomobject]@{device_a_id=1;device_b_id=2;fresh=$true});pending_nodes=@([pscustomobject]@{key='lldp:4:020000000003';system_name='new-neighbor';chassis=[pscustomobject]@{subtype=4;raw_hex='020000000003'}});pending_links=@([pscustomobject]@{local_device_id=1;remote_device_id=2},[pscustomobject]@{local_device_id=1;remote_key='lldp:4:020000000003';observed_at='2026-10-31T12:00:00Z'})}
$result=Select-TopologyScope $topology $scope
if($result.devices.Count -ne 1 -or $result.devices[0].id -ne 1 -or $result.links.Count -or $result.pending_links.Count){throw 'Excluded device/link leaked into scoped topology.'}
if($result.inventory_devices.Count -ne 1 -or -not $result.inventory_devices[0].observed_this_scan){throw 'Inventory projection lost allowed device.'}
if($result.neighbor_candidates.Count-ne 1 -or $result.neighbor_candidates[0].key-ne 'lldp:4:020000000003' -or $result.devices.Count-ne 1){throw 'New neighbor lost or promoted to confirmed device.'}
if($result.device_counts.confirmed-ne 1 -or $result.device_counts.collected_this_scan-ne 1 -or $result.device_counts.unconfirmed_neighbor_records-ne 1){throw 'Confirmed devices and unknown neighbor records were counted together.'}
Write-Output 'PASS: exact target whitelist; excluded history removed; address reuse does not replace chassis identity.'
