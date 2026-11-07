param([string]$PostgresBin='D:\PostgreSQL\bin',[ValidateRange(49152,65535)][int]$Port=55439,[switch]$Race,[string]$AcceptancePath='')
$ErrorActionPreference='Stop'
$taskRoot=(Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$runRoot=Join-Path $taskRoot ('.tools\tmp\lag-postgres-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
if(Test-Path -LiteralPath $runRoot){throw 'Test directory already exists'}
$null=New-Item -ItemType Directory -Path $runRoot
$dataPath=Join-Path $runRoot 'data'
$compileTemp=Join-Path $runRoot 'compile-tmp'
$null=New-Item -ItemType Directory -Path $compileTemp
$env:TEMP=$compileTemp;$env:TMP=$compileTemp;$env:TMPDIR=$compileTemp;$env:GOTMPDIR=$compileTemp
$logPath=Join-Path $runRoot 'postgres.log'
$pwPath=Join-Path $runRoot 'initial-password.txt'
$acceptance=Join-Path $taskRoot 'docs\acceptance\gonet-lag-adaptation'
if($AcceptancePath){$acceptance=[IO.Path]::GetFullPath($AcceptancePath,$taskRoot)}
$null=New-Item -ItemType Directory -Path $acceptance -Force
$testPassword=[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
[IO.File]::WriteAllText($pwPath,$testPassword)
$savedTestDSN=$env:GONET_TEST_DATABASE_URL
$savedIsolatedDSN=$env:GONET_ISOLATED_TEST_DATABASE_URL
$started=$false
Push-Location $taskRoot
try {
 & (Join-Path $PostgresBin 'initdb.exe') -D $dataPath -U gonet_lag_test -A scram-sha-256 --pwfile=$pwPath --encoding=UTF8 --locale=C *> (Join-Path $runRoot 'initdb.log')
 if($LASTEXITCODE -ne 0){throw 'Dedicated test cluster initialization failed; inspect initdb.log'}
 Remove-Item -LiteralPath $pwPath
 $arguments=@('-D',('"'+$dataPath+'"'),'-l',('"'+$logPath+'"'),'-o',('"-h 127.0.0.1 -p '+$Port+'"'),'-w','start')
 $launcher=Start-Process -FilePath (Join-Path $PostgresBin 'pg_ctl.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runRoot 'start.out') -RedirectStandardError (Join-Path $runRoot 'start.err')
 if(-not $launcher.WaitForExit(45000)){throw 'PostgreSQL launcher exceeded its deadline'}
 if($launcher.ExitCode -ne 0){throw 'Dedicated PostgreSQL did not start; inspect start.err'}
 $started=$true
 $env:GONET_TEST_DATABASE_URL='postgresql://gonet_lag_test:'+ $testPassword +'@127.0.0.1:'+ $Port +'/postgres?sslmode=disable'
 $env:GONET_ISOLATED_TEST_DATABASE_URL=$env:GONET_TEST_DATABASE_URL
 $env:GOCACHE=Join-Path $taskRoot '.gocache'
 $testArguments=@('test','-p','1','./cmd/...','./internal/...','./migrations/...','-count=1','-v')
 $logName='postgres-tests.log'
 if($Race){
  $mingw=Join-Path $taskRoot '.tools\mingw\mingw64\bin'
  $env:CC=Join-Path $mingw 'gcc.exe';$env:CGO_ENABLED='1';$env:PATH=$mingw+';'+$env:PATH
  if(-not(Test-Path -LiteralPath $env:CC)){throw 'Workspace MinGW compiler required for race checks'}
  $testArguments=@('test','-race','-p','1','./cmd/...','./internal/...','./migrations/...','-count=1','-v')
  $logName='postgres-race-tests.log'
 }
 & go @testArguments *> (Join-Path $acceptance $logName)
 $testExit=$LASTEXITCODE
 $runName=if($Race){'postgres-race-run.json'}else{'postgres-run.json'}
 [ordered]@{dedicated_instance=$true;business_database_contacted=$false;race=[bool]$Race;port=$Port;data_directory=$dataPath;test_exit_code=$testExit;finished_at=(Get-Date).ToString('o')} |ConvertTo-Json|Set-Content -LiteralPath (Join-Path $acceptance $runName) -Encoding utf8
 if($testExit -ne 0){Get-Content -LiteralPath (Join-Path $acceptance $logName)|Select-String 'FAIL|panic|\.go:' -Context 0,1;throw 'Isolated database test suite failed'}
 Write-Output 'PASS: dedicated PostgreSQL instance; all application packages and database integration tests.'
} finally {
 if($started){& (Join-Path $PostgresBin 'pg_ctl.exe') -D $dataPath -m fast -w stop *> (Join-Path $runRoot 'stop.log')}
 if(Test-Path -LiteralPath $pwPath){Remove-Item -LiteralPath $pwPath}
 $env:GONET_TEST_DATABASE_URL=$savedTestDSN
 $env:GONET_ISOLATED_TEST_DATABASE_URL=$savedIsolatedDSN
 $testPassword=$null
 Pop-Location
}
