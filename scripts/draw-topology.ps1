param([string]$Path,[string]$OutputDirectory,[string]$Title='gonet · LLDP 物理拓扑',[string]$Description='根据已核验的设备与端口证据展示物理连接。',[switch]$CoreOverview)
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
if(-not $Path){$Path=Join-Path $root 'outputs\topology-latest.json'}
if(-not $OutputDirectory){$OutputDirectory=Split-Path -Parent $Path}
$t=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $OutputDirectory|Out-Null
function Clean($text){return ([string]$text -replace '[\x00-\x1f\x7f-\x9f]',' ')}
function Escape($text){return [Security.SecurityElement]::Escape((Clean $text))}
function Csv-Text($text){$value=Clean $text;if($value-match '^[=+@-]'){$value="'"+$value};return $value}
function Kind-Label($kind){switch($kind){'router'{'路由器'} 'wireless_controller'{'无线 AC'} 'unknown'{'待核验'} default{'交换机'}}}
function Port-Label($key,$description){
 if($key -match '^lldp:5:([0-9a-f]+)$'){return [Text.Encoding]::UTF8.GetString([Convert]::FromHexString($Matches[1]))}
 if($key -match '^lldp:3:([0-9a-f]{12})$'){return (($Matches[1] -split '(.{2})'|Where-Object {$_})-join ':')}
 return (Clean $description)
}
$nodes=@{};$adj=@{};$inventoryByID=@{}
foreach($r in $t.inventory_devices){if($r.device_id){$inventoryByID[[string]$r.device_id]=$r}}
foreach($d in $t.devices){
 $id=[string]$d.id;$r=$inventoryByID[$id];$label=$d.sys_name;if($d.inventory_name){$label=$d.inventory_name}
 $model=$r.model;if($d.model){$model=$d.model}
 $nodes[$id]=[pscustomobject]@{id=$id;kind=$d.device_kind;name=$label;area=$d.area;address=($d.access_addresses -join ', ');model=$model;confirmed=$true;current=($null -ne $d.discovery_depth);x=0;y=0}
 $adj[$id]=[Collections.Generic.List[string]]::new()
}
foreach($r in $t.inventory_devices|Where-Object {-not $_.device_id}){
 $id='inventory-'+$r.row;$nodes[$id]=[pscustomobject]@{id=$id;kind='unknown';name=$r.name;area=$r.area;address=$r.address;model=$r.model;confirmed=$false;current=$false;x=0;y=0};$adj[$id]=[Collections.Generic.List[string]]::new()
}
$links=@($t.links)
foreach($l in $links){$a=[string]$l.device_a_id;$b=[string]$l.device_b_id;if($nodes.ContainsKey($a)-and $nodes.ContainsKey($b)){$adj[$a].Add($b);$adj[$b].Add($a)}}
$visited=@{};$components=[Collections.Generic.List[object]]::new();$isolated=[Collections.Generic.List[string]]::new()
foreach($start in @($nodes.Keys|Sort-Object)){
 if($visited[$start]){continue}
 $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($start);$visited[$start]=$true;$members=[Collections.Generic.List[string]]::new()
 while($queue.Count){$id=$queue.Dequeue();$members.Add($id);foreach($peer in $adj[$id]){if(-not $visited[$peer]){$visited[$peer]=$true;$queue.Enqueue($peer)}}}
 if($members.Count -eq 1){$isolated.Add($start)}else{$components.Add(@($members))}
}
$width=1740;$cardWidth=245;$cardHeight=94;$stepX=278;$stepY=150;$nextY=260;$sections=[Collections.Generic.List[object]]::new()
foreach($component in @($components|Sort-Object Count -Descending)){
 $rootID=@($component|Sort-Object @{Expression={if($nodes[$_].name -match '^核心交换机TS7914'){-1}elseif($nodes[$_].name -match '^(区域汇聚|内网汇聚)'){0}else{1}}},@{Expression={-$adj[$_].Count}},@{Expression={$nodes[$_].name}})[0]
 $levels=@{};$q=[Collections.Generic.Queue[string]]::new();$q.Enqueue($rootID);$levels[$rootID]=0
 while($q.Count){$id=$q.Dequeue();foreach($peer in $adj[$id]){if(-not $levels.ContainsKey($peer)){$levels[$peer]=1+$levels[$id];$q.Enqueue($peer)}}}
 $top=$nextY;$nextY+=50
 for($level=0;$level -le ($levels.Values|Measure-Object -Maximum).Maximum;$level++){
  $items=@($component|Where-Object {$levels[$_] -eq $level}|Sort-Object @{Expression={$nodes[$_].area}},@{Expression={$nodes[$_].name}})
  for($i=0;$i -lt $items.Count;$i++){
   $count=[Math]::Min(6,$items.Count-6*[Math]::Floor($i/6));$col=$i%6
   $n=$nodes[$items[$i]];$n.x=($width-$count*$stepX)/2+$col*$stepX+($stepX-$cardWidth)/2;$n.y=$nextY+[Math]::Floor($i/6)*$stepY
  }
  $nextY+=[Math]::Ceiling($items.Count/6)*$stepY
 }
 $sections.Add([pscustomobject]@{y=$top;height=($nextY-$top+14);title=('已确认连接组 · '+$nodes[$rootID].name);members=$component})
 $nextY+=52
}
if($isolated.Count){
 $top=$nextY;$nextY+=54;$items=@($isolated|Sort-Object @{Expression={$nodes[$_].area}},@{Expression={$nodes[$_].name}})
 for($i=0;$i -lt $items.Count;$i++){$n=$nodes[$items[$i]];$n.x=42+($i%6)*$stepX;$n.y=$nextY+[Math]::Floor($i/6)*$stepY}
 $nextY+=[Math]::Ceiling($items.Count/6)*$stepY
 $sections.Add([pscustomobject]@{y=$top;height=($nextY-$top+12);title='范围内未确认连接的设备（未画连线，不表示设备离线）';members=@($isolated)})
}
$height=$nextY+70
$svg=[Text.StringBuilder]::new();[void]$svg.AppendLine('<svg xmlns="http://www.w3.org/2000/svg" width="'+$width+'" height="'+$height+'" viewBox="0 0 '+$width+' '+$height+'">')
[void]$svg.AppendLine('<style>text{font-family:"Microsoft YaHei","Noto Sans CJK SC",sans-serif}.edge-label{paint-order:stroke;stroke:#f6f8fc;stroke-width:6px;stroke-linejoin:round}</style>')
$bitmap=$null;$graphics=$null
if($IsWindows){
 try{Add-Type -AssemblyName System.Drawing.Common;$bitmap=[Drawing.Bitmap]::new($width,$height);$graphics=[Drawing.Graphics]::FromImage($bitmap);$graphics.SmoothingMode='AntiAlias';$graphics.TextRenderingHint='AntiAliasGridFit'}catch{Write-Warning 'PNG 渲染不可用，仍会输出 SVG。'}
}
function Rect($x,$y,$w,$h,$fill,$stroke){
 [void]$svg.AppendLine('<rect x="'+$x+'" y="'+$y+'" width="'+$w+'" height="'+$h+'" rx="10" fill="'+$fill+'" stroke="'+$stroke+'"/>')
 if($graphics){$brush=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($fill));$pen=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml($stroke),1);$graphics.FillRectangle($brush,[single]$x,[single]$y,[single]$w,[single]$h);$graphics.DrawRectangle($pen,[single]$x,[single]$y,[single]$w,[single]$h);$brush.Dispose();$pen.Dispose()}
}
function Text($x,$y,$label,$size,$color,$bold=$false,$class=''){
 [void]$svg.AppendLine('<text x="'+$x+'" y="'+$y+'" font-size="'+$size+'" fill="'+$color+'" font-weight="'+$(if($bold){'600'}else{'400'})+'" class="'+$class+'">'+(Escape $label)+'</text>')
 if($graphics){$style=[Drawing.FontStyle]::Regular;if($bold){$style=[Drawing.FontStyle]::Bold};$font=[Drawing.Font]::new('Microsoft YaHei',[single]($size*0.75),$style);$brush=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($color));$graphics.DrawString((Clean $label),$font,$brush,[single]$x,[single]($y-$size));$font.Dispose();$brush.Dispose()}
}
Rect 0 0 $width $height '#f6f8fc' '#f6f8fc'
Text 42 55 $Title 32 '#14243c' $true
$generated=([DateTimeOffset]$t.generated_at).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
Text 42 90 ('扫描轮次 '+$t.latest_scan_id+' · '+$generated+' · 身份按 Chassis/端口匹配，地址仅用于采集') 16 '#5f6f86'
$bidirectional=@($links|Where-Object confidence -eq 'bidirectional').Count;$single=$links.Count-$bidirectional
Text 42 127 ('台账范围 '+$nodes.Count+' 台  /  已确认 '+$t.devices.Count+' 台  /  物理链路 '+$links.Count+' 条（双向 '+$bidirectional+'，单向 '+$single+'）') 20 '#14243c' $true
Text 42 161 $Description 16 '#5f6f86'
Text 42 194 '绿色实线：双向证据    橙色虚线：单向证据    灰线：历史链路    L 编号对应 topology-links.csv；SVG 悬停可看端口。' 15 '#5f6f86'
foreach($section in $sections){Rect 20 $section.y ($width-40) $section.height '#ffffff' '#dce3ee';Text 42 ($section.y+30) $section.title 18 '#283f61' $true}
$pairs=@{}
foreach($l in $links){
 $a=$nodes[[string]$l.device_a_id];$b=$nodes[[string]$l.device_b_id];if(-not $a -or -not $b){continue}
 $pair=[string]$l.device_a_id+'|'+$l.device_b_id;$index=0;if($pairs.ContainsKey($pair)){$index=$pairs[$pair]};$pairs[$pair]=$index+1
 $x1=$a.x+$cardWidth/2;$y1=$a.y+$cardHeight/2;$x2=$b.x+$cardWidth/2;$y2=$b.y+$cardHeight/2
 $dx=$x2-$x1;$dy=$y2-$y1;$length=[Math]::Max(1,[Math]::Sqrt($dx*$dx+$dy*$dy));$offset=($index*2-1)*24
 if([Math]::Abs($dy)-lt 10){$offset=80+$index*32}
 $cx=($x1+$x2)/2-$dy/$length*$offset;$cy=($y1+$y2)/2+$dx/$length*$offset
 $color='#18866a';$dash='';if($l.confidence -ne 'bidirectional'){$color='#c77a10';$dash=' stroke-dasharray="7 5"'};if(-not $l.fresh){$color='#9ba7b8'}
 $pa=Port-Label $l.port_a_key $l.port_a_name;$pb=Port-Label $l.port_b_key $l.port_b_name
 $tooltip='L'+$l.id+' | '+$a.name+' ['+$pa+'] ↔ '+$b.name+' ['+$pb+'] | '+$l.confidence
 if($CoreOverview){
  $coreNode=$a;$peerNode=$b;if($b.name -match '^核心交换机TS7914'){$coreNode=$b;$peerNode=$a}
  $startX=$coreNode.x+$cardWidth/2;$startY=$coreNode.y+$cardHeight
  $trackY=$startY+22+($index%2)*9;$busX=$peerNode.x-10-($index%2)*6
  $endY=$peerNode.y+$cardHeight/2+($index%2)*10-5
  $points=@(@($startX,$startY),@($startX,$trackY),@($busX,$trackY),@($busX,$endY),@($peerNode.x,$endY))
  $pathText='M '+($points[0]-join ' ');for($k=1;$k-lt $points.Count;$k++){$pathText+=' L '+($points[$k]-join ' ')}
  [void]$svg.AppendLine('<path d="'+$pathText+'" fill="none" stroke="'+$color+'" stroke-width="1.8"'+$dash+'><title>'+(Escape $tooltip)+'</title></path>')
  if($graphics){$pen=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml($color),1.8);if($dash){$pen.DashStyle='Dash'};[Drawing.PointF[]]$drawPoints=@($points|ForEach-Object {[Drawing.PointF]::new([single]$_[0],[single]$_[1])});$graphics.DrawLines($pen,$drawPoints);$pen.Dispose()}
  Text ($peerNode.x+12+$index*65) ($peerNode.y-9) ('L'+$l.id) 12 $color $true 'edge-label'
  continue
 }
 [void]$svg.AppendLine('<path d="M '+$x1+' '+$y1+' Q '+$cx+' '+$cy+' '+$x2+' '+$y2+'" fill="none" stroke="'+$color+'" stroke-width="2.3"'+$dash+'><title>'+(Escape $tooltip)+'</title></path>')
 if($graphics){$pen=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml($color),2.3);if($dash){$pen.DashStyle='Dash'};$graphics.DrawBezier($pen,[single]$x1,[single]$y1,[single]($x1+2*($cx-$x1)/3),[single]($y1+2*($cy-$y1)/3),[single]($x2+2*($cx-$x2)/3),[single]($y2+2*($cy-$y2)/3),[single]$x2,[single]$y2);$pen.Dispose()}
 Text (($x1+2*$cx+$x2)/4) (($y1+2*$cy+$y2)/4-6) ('L'+$l.id) 12 $color $true 'edge-label'
}
foreach($n in $nodes.Values){
 $fill='#edf5ff';$stroke='#a6c7e9';$state='';if(-not $n.confirmed){$fill='#fff3ee';$stroke='#e8a78d';$state='未确认采集'}elseif(-not $n.current){$fill='#f3f4f6';$stroke='#b8c0cd';$state='本轮未确认 / 历史设备'}
 if($n.confirmed -and $n.current -and $n.name -match '^核心交换机TS7914'){$fill='#dceafe';$stroke='#2b62b0';$state='双机堆叠 · 一个 LLDP chassis'}
 Rect $n.x $n.y $cardWidth $cardHeight $fill $stroke
 $name=Clean $n.name;$lines=[Collections.Generic.List[string]]::new();$line='';$units=0
 foreach($ch in $name.ToCharArray()){$u=1;if([int]$ch-gt 255){$u=2};if($units+$u-gt 27){$lines.Add($line);$line='';$units=0};$line+=$ch;$units+=$u};if($line){$lines.Add($line)}
 Text ($n.x+12) ($n.y+23) $lines[0] 14 '#193b60' $true
 if($lines.Count -gt 1){Text ($n.x+12) ($n.y+43) ($lines[1]+$(if($lines.Count-gt 2){'…'}else{''})) 14 '#193b60' $true}
 Text ($n.x+12) ($n.y+65) $n.address 13 '#47617e'
 $detail=$n.area+' · '+$n.model;if($state){$detail=$state}
 Text ($n.x+12) ($n.y+84) $detail 11 '#6c7e94'
}
Text 42 ($height-24) ('未确认连接不补线；并行物理链路分别保留。范围内待匹配观察 '+$t.pending_links.Count+' 条。') 14 '#5f6f86'
[void]$svg.AppendLine('</svg>')
$svgPath=Join-Path $OutputDirectory 'topology-latest.svg';[IO.File]::WriteAllText($svgPath,$svg.ToString(),[Text.UTF8Encoding]::new($false))
if($graphics){$graphics.Dispose();try{$bitmap.Save((Join-Path $OutputDirectory 'topology-latest.png'),[Drawing.Imaging.ImageFormat]::Png)}finally{$bitmap.Dispose()}}
$nodes.Values|Sort-Object area,name|ForEach-Object {$n=$_;$status=if(-not $n.confirmed){'unconfirmed'}elseif($n.current){'collected'}else{'historical'};[pscustomobject]@{区域=(Csv-Text $n.area);设备=(Csv-Text $n.name);采集地址=$n.address;型号=(Csv-Text $n.model);设备ID=$(if($n.confirmed){$n.id}else{''});状态=$status;物理链路数=$adj[$n.id].Count;设备类型=(Kind-Label $n.kind)}}|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'topology-devices.csv') -NoTypeInformation -Encoding utf8BOM
$links|ForEach-Object {$l=$_;$a=$nodes[[string]$l.device_a_id];$b=$nodes[[string]$l.device_b_id];[pscustomobject]@{链路=('L'+$l.id);设备A=$a.name;端口A=(Port-Label $l.port_a_key $l.port_a_name);端口描述A=$l.port_a_name;设备B=$b.name;端口B=(Port-Label $l.port_b_key $l.port_b_name);端口描述B=$l.port_b_name;证据=$l.confidence;本轮观察=$l.fresh;状态=$l.discovery_state}}|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'topology-links.csv') -NoTypeInformation -Encoding utf8BOM
Write-Host ('拓扑图：'+$svgPath)
if($null-ne $t.neighbor_candidates){
 $candidatePath=Join-Path $OutputDirectory 'topology-neighbor-candidates.csv'
 if(@($t.neighbor_candidates).Count){
  $t.neighbor_candidates|ForEach-Object {$kind='待识别';if($_.device_kind){$kind=Kind-Label $_.device_kind};[pscustomobject]@{邻居名称=(Csv-Text $_.system_name);Chassis标识=$_.key;原始类型=$_.chassis_subtype;原始字节=$_.chassis_hex;发现来源=(Csv-Text ($_.observed_by-join '、'));状态='待核验，不计已确认设备数';观察时间=$_.observed_at;设备类型=$kind;型号=(Csv-Text $_.model)}}|Export-Csv -LiteralPath $candidatePath -NoTypeInformation -Encoding utf8BOM
 }else{[IO.File]::WriteAllText($candidatePath,'"邻居名称","Chassis标识","原始类型","原始字节","发现来源","状态","观察时间","设备类型","型号"'+"`r`n",[Text.UTF8Encoding]::new($true))}
}
