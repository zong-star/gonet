param([string]$BaseUrl='')
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$path=Join-Path $root 'outputs\console-process.json'
if(-not(Test-Path -LiteralPath $path)){Write-Host '未找到本脚本启动的控制台。';exit 0}
$record=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;$process=Get-Process -Id $record.pid -ErrorAction SilentlyContinue
if(-not $process){Write-Host '控制台已停止。';exit 0}
if($process.Path-ne (Join-Path $root 'gonet.exe') -or $process.StartTime.ToUniversalTime().Ticks-ne ([DateTimeOffset]$record.started_at).UtcDateTime.Ticks){throw '进程与启动记录不符，未停止任何进程。'}
$listenHost=$record.listen_host
if(-not $listenHost){$listenHost='127.0.0.1'}
if($BaseUrl){$parsed=[uri]$BaseUrl;if($parsed.Scheme-ne 'https' -or $parsed.UserInfo -or $parsed.Query -or $parsed.Fragment -or $parsed.AbsolutePath-ne '/'){throw 'BaseUrl 必须是可信 HTTPS 站点根地址。'};$url=$BaseUrl.TrimEnd('/')}
else{
 $listenIP=$null
 $scheme='http'
 if(-not [ipaddress]::TryParse($listenHost,[ref]$listenIP)){throw '启动记录中的监听地址无效。'}
 if($record.scheme -eq 'https'){$scheme='https'}
 if(-not [ipaddress]::IsLoopback($listenIP)){
  if($scheme -ne 'https'){throw '内网停止请求必须使用 HTTPS。'}
  $socket=Get-NetTCPConnection -OwningProcess $process.Id -State Listen -LocalPort $record.port -LocalAddress $listenIP.ToString() -ErrorAction SilentlyContinue
  if(-not $socket){throw '启动记录中的内网监听与实际进程不符。'}
 }
 $url=([UriBuilder]::new($scheme,$listenIP.ToString(),[int]$record.port)).Uri.GetLeftPart([UriPartial]::Authority)
}
$username=Read-Host '管理员用户名'
$securePassword=Read-Host '管理员密码' -AsSecureString
$session=New-Object Microsoft.PowerShell.Commands.WebRequestSession
$csrf='';$loggedIn=$false
try{
 $plainPassword=([pscredential]::new($username,$securePassword)).GetNetworkCredential().Password
 $loginBody=@{username=$username;password=$plainPassword}|ConvertTo-Json -Compress
 $login=Invoke-RestMethod -Uri ($url+'/api/v1/auth/login') -Method Post -WebSession $session -Headers @{'X-GoNet-Login'='1'} -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($loginBody)) -TimeoutSec 10 -NoProxy
 $loggedIn=$true;$csrf=$login.csrf_token;$login=$null;$plainPassword=$null;$loginBody=$null
 $state=Invoke-RestMethod -Uri ($url+'/api/state') -WebSession $session -TimeoutSec 12 -NoProxy
 if($null-eq $state.job -or $state.job.running -isnot [bool]){throw '任务状态响应无效。'}
 if($state.job.running){Invoke-RestMethod -Uri ($url+'/api/cancel') -WebSession $session -Method Post -Headers @{'X-GoNet-Token'=$csrf} -ContentType 'application/json' -Body '{}' -TimeoutSec 5 -NoProxy|Out-Null
  for($i=0;$i-lt 30;$i++){Start-Sleep -Milliseconds 500;$state=Invoke-RestMethod -Uri ($url+'/api/state') -WebSession $session -TimeoutSec 12 -NoProxy;if($null-eq $state.job -or $state.job.running -isnot [bool]){throw '任务状态响应无效。'};if(-not $state.job.running){break}}
  if($state.job.running){throw '任务仍在保存，请稍后再次停止。'}
 }
}catch{if($_.Exception.Message-match '任务仍在保存'){throw};throw '认证失败或无法确认扫描状态，未停止进程。核对账号和 Cookie 模式；Secure Cookie 请使用 -BaseUrl 指定可信 HTTPS 入口。'}
finally{
 if($loggedIn){try{Invoke-WebRequest -Uri ($url+'/api/v1/auth/logout') -WebSession $session -Method Post -Headers @{'X-GoNet-Token'=$csrf} -ContentType 'application/json' -Body '{}' -TimeoutSec 5 -NoProxy|Out-Null}catch{}}
 $plainPassword=$null;$loginBody=$null;$csrf=$null;$session=$null;$securePassword.Dispose()
}
Stop-Process -Id $process.Id
if(-not $process.HasExited){$process.WaitForExit(5000)|Out-Null}
Write-Host 'GoNet 控制台已停止。'
