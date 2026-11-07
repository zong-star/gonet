param([ValidateRange(1024,65535)][int]$Port=8787,[switch]$NoBrowser,[switch]$Foreground,[string]$ListenHost,[string]$AllowedSources,[string]$TLSCert,[string]$TLSKey,[string]$TLSCA)
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$binary=Join-Path $root 'gonet.exe';$configPath=Join-Path $root 'config.yaml';$scopePath=Join-Path $root 'config\scan-scope.json';$output=Join-Path $root 'outputs'
if(-not(Test-Path -LiteralPath $binary)){throw '请先构建或解压带 gonet.exe 的开发包。'}
$listenerPath=Join-Path $root 'config\console-listener.json'
if(Test-Path -LiteralPath $listenerPath){
 $listenerConfig=Get-Content -LiteralPath $listenerPath -Raw | ConvertFrom-Json
 if(-not $PSBoundParameters.ContainsKey('ListenHost')){$ListenHost=$listenerConfig.listen_host}
 if(-not $PSBoundParameters.ContainsKey('AllowedSources')){$AllowedSources=$listenerConfig.allowed_sources}
 if(-not $PSBoundParameters.ContainsKey('TLSCert')){$TLSCert=$listenerConfig.tls_cert}
 if(-not $PSBoundParameters.ContainsKey('TLSKey')){$TLSKey=$listenerConfig.tls_key}
 if(-not $PSBoundParameters.ContainsKey('TLSCA')){$TLSCA=$listenerConfig.tls_ca}
}
if(-not $ListenHost){$ListenHost='127.0.0.1'}
$listenIP=$null
if(-not [ipaddress]::TryParse($ListenHost,[ref]$listenIP)){throw '监听地址必须是 IP 地址。'}
$ListenHost=$listenIP.ToString()
if($AllowedSources -and $AllowedSources -notmatch '\A[0-9A-Fa-f:.,/]+\z'){throw '访问来源须为以逗号分隔的 IP 地址或 CIDR 网段。'}
$scheme='http'
function Resolve-TLSPath([string]$path){
 if(-not [IO.Path]::IsPathRooted($path)){$path=Join-Path $root $path}
 return (Resolve-Path -LiteralPath $path).Path
}
if($TLSCert -or $TLSKey -or $TLSCA){
 if(-not ($TLSCert -and $TLSKey -and $TLSCA)){throw 'HTTPS 启动需要 TLS 证书、私钥和用于健康检查的 CA 证书。'}
 $TLSCert=Resolve-TLSPath $TLSCert
 $TLSKey=Resolve-TLSPath $TLSKey
 $TLSCA=Resolve-TLSPath $TLSCA
 $scheme='https'
}
if($scheme -eq 'http' -and -not [ipaddress]::IsLoopback($listenIP)){throw '内网监听必须使用 HTTPS。'}
$endpoint=[UriBuilder]::new($scheme,$ListenHost,$Port)
$url=$endpoint.Uri.GetLeftPart([UriPartial]::Authority)
$listen=$endpoint.Uri.Authority
$text=[IO.File]::ReadAllText($configPath)
foreach($match in [regex]::Matches($text,'(?m)^\s*[a-z_]+_env:\s*[''"]?([A-Za-z_][A-Za-z0-9_]*)')){$name=$match.Groups[1].Value;$value=[Environment]::GetEnvironmentVariable($name,'User');if($value){[Environment]::SetEnvironmentVariable($name,$value,'Process')}}
foreach($name in @('GONET_ADMIN_USERNAME','GONET_ADMIN_PASSWORD_HASH','GONET_SESSION_TTL','GONET_COOKIE_SECURE','GONET_TRUSTED_PROXY_CIDRS','GONET_AGENT_API_ENABLED','GONET_AGENT_READ_TOKEN_SHA256')){
 if(-not [Environment]::GetEnvironmentVariable($name,'Process')){$value=[Environment]::GetEnvironmentVariable($name,'User');if($value){[Environment]::SetEnvironmentVariable($name,$value,'Process')}}
}
$authFile=Join-Path $root 'config\console-auth.dpapi.xml'
if(Test-Path -LiteralPath $authFile){
 $authConfig=Import-Clixml -LiteralPath $authFile
 $authNames=@('GONET_ADMIN_USERNAME','GONET_ADMIN_PASSWORD_HASH','GONET_SESSION_TTL','GONET_COOKIE_SECURE','GONET_AGENT_API_ENABLED','GONET_AGENT_READ_TOKEN_SHA256')
 if($authConfig.Version-ne 1 -or $authConfig.Environment-isnot [Collections.IDictionary]){throw '本机加密认证配置格式无效。'}
 foreach($name in $authConfig.Environment.Keys){
  if($name-notin $authNames){throw '本机加密认证配置包含不支持的字段。'}
  $value=$authConfig.Environment[$name]
  if($name-eq 'GONET_ADMIN_PASSWORD_HASH' -or $name-eq 'GONET_AGENT_READ_TOKEN_SHA256'){
   if($value-isnot [Security.SecureString]){throw '本机认证摘要必须采用 DPAPI 加密保存。'}
   $value=([pscredential]::new('encrypted-config',$value)).GetNetworkCredential().Password
  }elseif($value-isnot [string]){throw '本机加密认证配置值无效。'}
  if(-not [Environment]::GetEnvironmentVariable($name,'Process')){[Environment]::SetEnvironmentVariable($name,$value,'Process')}
 }
 $value=$null;$authConfig=$null
}
function Test-ConsoleHealth{
 try{
  if($scheme -eq 'https'){
   $body=curl.exe --noproxy '*' --cacert $TLSCA --ssl-revoke-best-effort --fail --silent --max-time 2 ($url+'/health')
   return $LASTEXITCODE -eq 0 -and ($body | ConvertFrom-Json).ok -eq $true
  }
  return (Invoke-RestMethod -Uri ($url+'/health') -TimeoutSec 2 -NoProxy).ok -eq $true
 }catch{return $false}
}
$already=Test-ConsoleHealth
if(-not $already){
 if(-not $env:GONET_ADMIN_USERNAME -or -not $env:GONET_ADMIN_PASSWORD_HASH){throw '缺少 GONET_ADMIN_USERNAME / GONET_ADMIN_PASSWORD_HASH。先运行 gonet auth hash-password，并配置认证环境变量。'}
 if($scheme -eq 'https'){$env:GONET_COOKIE_SECURE='true'}
 elseif($env:GONET_COOKIE_SECURE -ne 'false'){throw '本脚本使用回环 HTTP，须显式设置 GONET_COOKIE_SECURE=false。'}
 New-Item -ItemType Directory -Force -Path $output|Out-Null
 $accessArguments=@('--listen',$listen)
 if($AllowedSources){$accessArguments+=@('--allow-sources',$AllowedSources)}
 if($scheme -eq 'https'){$accessArguments+=@('--tls-cert',$TLSCert,'--tls-key',$TLSKey)}
 $processAccessArguments=$accessArguments | ForEach-Object {if($_ -match '\s'){'"'+$_+'"'}else{$_}}
 $arguments=@('serve','--config',('"'+$configPath+'"'),'--scope',('"'+$scopePath+'"'),'--output-dir',('"'+$output+'"'))+$processAccessArguments
 if($Foreground){Push-Location $root;try{& $binary serve --config $configPath --scope $scopePath --output-dir $output @accessArguments;exit $LASTEXITCODE}finally{Pop-Location}}
 $process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $output 'console.log') -RedirectStandardError (Join-Path $output 'console-error.log') -PassThru
 @{pid=$process.Id;started_at=$process.StartTime.ToUniversalTime().ToString('o');port=$Port;listen_host=$ListenHost;scheme=$scheme}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'console-process.json') -Encoding utf8
 for($i=0;$i-lt 30;$i++){if(Test-ConsoleHealth){$already=$true;break};if($process.HasExited){break};Start-Sleep -Milliseconds 200}
 if(-not $already){throw '控制台未启动，请查看 outputs\console-error.log。'}
}
Write-Host ('GoNet 控制台：'+$url)
if(-not $NoBrowser){Start-Process $url}
