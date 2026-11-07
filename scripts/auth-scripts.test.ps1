# Isolated operational-script regression: real HTTP auth, mocked OS processes.
# Start TestAuthBrowserFixture first. Never points at the production port.
$ErrorActionPreference='Stop'
$workspace=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$fixtureRoot=Join-Path $workspace '.tools\tmp\auth-script-test'
New-Item -ItemType Directory -Force -Path (Join-Path $fixtureRoot 'scripts'),(Join-Path $fixtureRoot 'outputs'),(Join-Path $fixtureRoot 'config')|Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'start-ui.ps1'),(Join-Path $PSScriptRoot 'stop-ui.ps1') -Destination (Join-Path $fixtureRoot 'scripts')
Set-Content -LiteralPath (Join-Path $fixtureRoot 'config.yaml') -Value '# no real device or database credentials'
Set-Content -LiteralPath (Join-Path $fixtureRoot 'gonet.exe') -Value 'mock process; never executed'
$script:stopCount=0;$script:startCount=0;$script:healthMiss=$true;$script:runningOnce=$false;$script:badLogin=$false
$script:fakeProcess=[pscustomobject]@{Id=424242;StartTime=[datetime]::UtcNow;HasExited=$false;Path=(Join-Path $fixtureRoot 'gonet.exe')}
$script:fakeProcess|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($timeout) $true}
function Start-Process {param($FilePath,$ArgumentList,$WorkingDirectory,$WindowStyle,$RedirectStandardOutput,$RedirectStandardError,[switch]$PassThru)
 if($FilePath-ne $script:fakeProcess.Path -or $WindowStyle-ne 'Hidden'){throw 'unsafe or visible launch'};$script:startCount++;return $script:fakeProcess
}
function Get-Process {param($Id,$ErrorAction) if($Id-eq 424242){return $script:fakeProcess};throw 'unexpected process lookup'}
function Stop-Process {param($Id) if($Id-ne 424242){throw 'unexpected process stop'};$script:stopCount++;$script:fakeProcess.HasExited=$true}
function Read-Host {param($Prompt,[switch]$AsSecureString) if($AsSecureString){if($script:badLogin){return ConvertTo-SecureString 'wrong-fixture-password' -AsPlainText -Force};return ConvertTo-SecureString 'fixture-password-2026' -AsPlainText -Force};return 'admin'}
function Invoke-RestMethod {
 param($Uri,$Method='Get',$WebSession,$Headers,$ContentType,$Body,$TimeoutSec,[switch]$NoProxy)
 if(-not ([string]$Uri).StartsWith('http://127.0.0.1:18787/')){throw 'unexpected network target'}
 if(([string]$Uri).EndsWith('/health') -and $script:healthMiss){$script:healthMiss=$false;throw 'simulate not started'}
 $args=@{Uri=$Uri;Method=$Method;TimeoutSec=$TimeoutSec;NoProxy=$true};foreach($key in @('WebSession','Headers','ContentType','Body')){if($PSBoundParameters.ContainsKey($key)){$args[$key]=$PSBoundParameters[$key]}}
 $result=Microsoft.PowerShell.Utility\Invoke-RestMethod @args
 if(([string]$Uri).EndsWith('/api/state') -and $script:runningOnce){$result.job.running=$true;$script:runningOnce=$false}
 return $result
}
$savedUsername=$env:GONET_ADMIN_USERNAME;$savedHash=$env:GONET_ADMIN_PASSWORD_HASH;$savedSecure=$env:GONET_COOKIE_SECURE
$savedAgentEnabled=$env:GONET_AGENT_API_ENABLED;$env:GONET_AGENT_API_ENABLED='false'
try{
 $env:GONET_ADMIN_USERNAME='admin';$env:GONET_ADMIN_PASSWORD_HASH='fixture-launch-placeholder';$env:GONET_COOKIE_SECURE='false'
 . (Join-Path $fixtureRoot 'scripts\start-ui.ps1') -Port 18787 -NoBrowser
 if($script:startCount-ne 1){throw 'start was not hidden or not executed'}
 $script:runningOnce=$true
 . (Join-Path $fixtureRoot 'scripts\stop-ui.ps1')
 if($script:stopCount-ne 1){throw 'authenticated idle stop failed'}
 $script:fakeProcess.HasExited=$false;$script:badLogin=$true;$refused=$false
 try{. (Join-Path $fixtureRoot 'scripts\stop-ui.ps1')}catch{$refused=$true}
 if(-not $refused -or $script:stopCount-ne 1){throw 'authentication failure did not refuse stop'}
 $script:badLogin=$false;$script:fakeProcess.Path='unexpected.exe';$refused=$false
 try{. (Join-Path $fixtureRoot 'scripts\stop-ui.ps1')}catch{$refused=$true}
 if(-not $refused -or $script:stopCount-ne 1){throw 'process identity guard failed'}
 # Also exercise the actual OS launch/identity/stop against a compiled helper
 # that links the real webui and auth packages and has no database/collector.
 foreach($functionName in @('Start-Process','Get-Process','Stop-Process','Invoke-RestMethod')){Remove-Item -LiteralPath ('Function:\'+$functionName)}
 $realRoot=Join-Path $fixtureRoot 'real'
 New-Item -ItemType Directory -Force -Path (Join-Path $realRoot 'scripts'),(Join-Path $realRoot 'outputs'),(Join-Path $realRoot 'config')|Out-Null
 Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'start-ui.ps1'),(Join-Path $PSScriptRoot 'stop-ui.ps1') -Destination (Join-Path $realRoot 'scripts')
 Set-Content -LiteralPath (Join-Path $realRoot 'config.yaml') -Value '# isolated fixture only'
 $helperSource=@'
package main
import("context";"flag";"net/http";"os";"time";"gonet/internal/auth";"gonet/internal/control";"gonet/internal/webui")
type backend struct{}
func(backend)Read(context.Context)(*control.View,error){return &control.View{},nil}
func(backend)Settings()control.Settings{return control.Settings{}}
func(backend)SaveSettings(control.Settings)error{return nil}
func(backend)Scan(context.Context,bool,func(webui.Progress))(webui.RunResult,error){panic("fixture cannot scan")}
func main(){
 if len(os.Args)==3&&os.Args[1]=="fixture-hash"{h,e:=auth.HashPassword([]byte("fixture-password-2026"));if e!=nil{panic(e)};if e=os.WriteFile(os.Args[2],h,0600);e!=nil{panic(e)};return}
 f:=flag.NewFlagSet("serve",flag.ExitOnError);listen:=f.String("listen","127.0.0.1:18789","");f.String("config","","");f.String("scope","","");f.String("output-dir","","");f.Parse(os.Args[2:])
 c,e:=auth.LoadConfig();if e!=nil{panic("fixture auth config invalid")};app,e:=webui.New(context.Background(),backend{},c);if e!=nil{panic(e)};defer app.Close()
 server:=&http.Server{Addr:*listen,Handler:app.Handler(*listen),ReadHeaderTimeout:5*time.Second};if e=server.ListenAndServe();e!=nil{panic(e)}
}
'@
 $helperPath=Join-Path $realRoot 'main.go';Set-Content -LiteralPath $helperPath -Value $helperSource
 & go build -o (Join-Path $realRoot 'gonet.exe') $helperPath
 if($LASTEXITCODE-ne 0){throw 'helper compilation failed'}
 & (Join-Path $realRoot 'gonet.exe') fixture-hash (Join-Path $realRoot 'fixture.hash')
 $protectedFile=Join-Path $realRoot 'config\console-auth.dpapi.xml'
 $fixtureHash=[IO.File]::ReadAllText((Join-Path $realRoot 'fixture.hash'))
 @{Version=1;Environment=@{GONET_ADMIN_USERNAME='admin';GONET_ADMIN_PASSWORD_HASH=(ConvertTo-SecureString $fixtureHash -AsPlainText -Force);GONET_COOKIE_SECURE='false';GONET_AGENT_API_ENABLED='false'}}|Export-Clixml -LiteralPath $protectedFile
 $fixtureHash=$null;$env:GONET_ADMIN_USERNAME=$null;$env:GONET_ADMIN_PASSWORD_HASH=$null
 . (Join-Path $realRoot 'scripts\start-ui.ps1') -Port 18789 -NoBrowser
 if($env:GONET_ADMIN_USERNAME-ne 'admin' -or -not $env:GONET_ADMIN_PASSWORD_HASH){throw 'DPAPI authentication file was not loaded'}
 $liveRecord=Get-Content -LiteralPath (Join-Path $realRoot 'outputs\console-process.json') -Raw|ConvertFrom-Json
 if(-not(Get-Process -Id $liveRecord.pid -ErrorAction SilentlyContinue)){throw 'actual fixture process did not start'}
 . (Join-Path $realRoot 'scripts\stop-ui.ps1')
 if(Get-Process -Id $liveRecord.pid -ErrorAction SilentlyContinue){throw 'actual fixture process did not stop'}
 foreach($invalid in @(@{Version=0;Environment=@{}},@{Version=1;Environment=@{GONET_ADMIN_PASSWORD_HASH='invalid-unprotected-fixture'}})){
  $invalid|Export-Clixml -LiteralPath $protectedFile;$refused=$false
  try{. (Join-Path $realRoot 'scripts\start-ui.ps1') -Port 18789 -NoBrowser}catch{$refused=$true}
  if(-not $refused){throw 'invalid protected authentication config was accepted'}
 }
 Remove-Item -LiteralPath $protectedFile
 $results=@{passed=8;hidden_launch=$true;authenticated_cancel_and_stop=$true;auth_failure_refuses_stop=$true;process_identity_refuses_stop=$true;actual_os_start_stop=$true;http_auth_real=$true;no_database_or_collector=$true;dpapi_config_load=$true;invalid_dpapi_version_refused=$true;unprotected_hash_refused=$true}
 $results|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $workspace 'docs\acceptance\auth-2026-11-02\script-results.json')
 Write-Host 'PASS 8 isolated operational script checks (including DPAPI and actual OS start/stop)'
}finally{$env:GONET_ADMIN_USERNAME=$savedUsername;$env:GONET_ADMIN_PASSWORD_HASH=$savedHash;$env:GONET_COOKIE_SECURE=$savedSecure;$env:GONET_AGENT_API_ENABLED=$savedAgentEnabled}
