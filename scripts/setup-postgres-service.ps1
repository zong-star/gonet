param(
    [ValidatePattern('^[a-z][a-z0-9_]{0,62}$')][string]$DatabaseName = 'gonet',
    [ValidatePattern('^[a-z][a-z0-9_]{0,62}$')][string]$AppRole = 'gonet_app',
    [ValidatePattern('^[a-zA-Z_][a-zA-Z0-9_]{0,62}$')][string]$AdminUser = 'postgres',
    [switch]$ValidateOnly,
    [switch]$DatabaseOnly,
    [string]$PreviousAppRole
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$statusPath = Join-Path $root '.tools\postgres-service-setup-status.json'
$adminStatus = Join-Path $root '.tools\postgres-service-admin-status.json'
$psql = 'D:\PostgreSQL\bin\psql.exe'
$configPath = Join-Path $root 'config.yaml'
$adminPassword = $null
$appPassword = $null

function Write-State([string]$Stage, [string]$Message) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $statusPath) | Out-Null
    @{ stage = $Stage; message = $Message; port = 5432; database = $DatabaseName; role = $AppRole; updated_at = (Get-Date).ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
}

function Read-LocalPassword([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $buffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($buffer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($buffer); $secure.Dispose() }
}

function Invoke-Database([string]$Username, [string]$Password, [string]$Db, [string]$Sql) {
    $previousPassword = $env:PGPASSWORD
    $previousTimeout = $env:PGCONNECT_TIMEOUT
    try {
        $env:PGPASSWORD = $Password
        $env:PGCONNECT_TIMEOUT = '5'
        $output = $Sql | & $psql -X -w -h 127.0.0.1 -p 5432 -U $Username -d $Db -v ON_ERROR_STOP=1 -Atq 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Never echo a SQL payload or a password on errors.
            throw "Database operation failed for user '$Username' on '$Db'. Check the local password and database permissions."
        }
        return (($output | ForEach-Object { $_.ToString() }) -join "`n").Trim()
    } finally { $env:PGPASSWORD = $previousPassword; $env:PGCONNECT_TIMEOUT = $previousTimeout }
}

try {
    if ($PreviousAppRole -and $PreviousAppRole -notmatch '^[a-z][a-z0-9_]{0,62}$') { throw 'Invalid previous application role name.' }
    if (-not (Test-Path -LiteralPath $psql)) { throw 'PostgreSQL client not found at D:\PostgreSQL\bin.' }
    if ($ValidateOnly) {
        & (Join-Path $PSScriptRoot 'postgres-service-admin.ps1') -ValidateOnly
        exit $LASTEXITCODE
    }
    Write-Host 'GoNet：切换到现有 PostgreSQL Windows 服务（127.0.0.1:5432）。' -ForegroundColor Cyan
    if ($DatabaseOnly) {
        Write-Host '旧项目测试实例已清理；本次只配置现有服务上的业务库。'
        if (Test-Path -LiteralPath (Join-Path $root '.pgdata')) { throw 'Test cluster is still present; run the full setup first.' }
        $service = Get-CimInstance Win32_Service -Filter "Name='postgresql-x64-18'"
        if ($service.State -ne 'Running') { throw 'Start the PostgreSQL Windows service before database-only setup.' }
        & 'D:\PostgreSQL\bin\pg_isready.exe' -h 127.0.0.1 -p 5432 -t 3
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL is not accepting connections on 5432.' }
    } else {
        Write-Host '将删除项目 .pgdata 测试实例及其中的测试库，不删除 D:\PostgreSQL\data。'
        Write-State 'waiting_admin' 'Windows UAC authorization is required to start the service and remove the test instance.'
        $engine = (Get-Command pwsh).Source
        $adminScript = Join-Path $PSScriptRoot 'postgres-service-admin.ps1'
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $adminScript + '"'
        $admin = Start-Process -FilePath $engine -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if ($admin.ExitCode -ne 0) { throw 'Administrator step did not finish. See .tools/postgres-service-admin-status.json.' }
        if (-not (Test-Path -LiteralPath $adminStatus) -or (Get-Content -Raw -LiteralPath $adminStatus | ConvertFrom-Json).stage -ne 'complete') {
            throw 'Administrator step was not verified.'
        }
    }

    foreach ($name in @('GONET_DATABASE_URL', 'GONET_TEST_DATABASE_URL')) {
        foreach ($scope in @('Process', 'User')) {
            $value = [Environment]::GetEnvironmentVariable($name, $scope)
            if ($value) {
                try { $uri = [Uri]$value } catch { continue }
                if ($uri.Host -in @('127.0.0.1', 'localhost', '::1') -and $uri.Port -eq 55432) {
                    [Environment]::SetEnvironmentVariable($name, $null, $scope)
                }
            }
        }
    }

    Write-State 'waiting_password' 'Enter the existing PostgreSQL administrator password in this local window.'
    Write-Host '服务和清理步骤已完成。请在本机输入已有数据库密码，不要发送到聊天。'
    $adminPassword = Read-LocalPassword "请输入 PostgreSQL 管理员 $AdminUser 的现有密码"
    if (-not $adminPassword) { throw 'Password is required. The service is running; setup can be run again.' }
    $null = Invoke-Database $AdminUser $adminPassword 'postgres' 'SELECT 1;'

    Write-State 'configuring_database' 'Creating an application-owned project database without altering existing database passwords.'
    $owner = Invoke-Database $AdminUser $adminPassword 'postgres' "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DatabaseName';"
    while ($owner -and $owner -ne $AppRole) {
        Write-Host "数据库 $DatabaseName 已属于其他账号，不会覆盖。" -ForegroundColor Yellow
        $candidateName = Read-Host '请为本项目输入另一个数据库名（小写字母/数字/下划线，留空退出）'
        if (-not $candidateName) { throw 'Existing database preserved. No replacement database name provided.' }
        if ($candidateName -notmatch '^[a-z][a-z0-9_]{0,62}$') { Write-Host '数据库名格式不正确。'; continue }
        $DatabaseName = $candidateName
        $owner = Invoke-Database $AdminUser $adminPassword 'postgres' "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DatabaseName';"
    }
    $exists = Invoke-Database $AdminUser $adminPassword 'postgres' "SELECT count(*) FROM pg_roles WHERE rolname='$AppRole';"
    if ($PreviousAppRole -and $PreviousAppRole -ne $AppRole) {
        # Reuse only this project's saved local credential. Never reset or
        # rename an unrelated role, or rename a role that still owns a database.
        $previousDsn = [Environment]::GetEnvironmentVariable('GONET_DATABASE_URL', 'User')
        if (-not $previousDsn) { throw 'Previous application credential is not configured.' }
        $previousUri = [Uri]$previousDsn
        $previousParts = $previousUri.UserInfo.Split(':', 2)
        if ($previousUri.Host -ne '127.0.0.1' -or $previousUri.Port -ne 5432 -or $previousParts.Length -ne 2 -or
            [Uri]::UnescapeDataString($previousParts[0]) -ne $PreviousAppRole) { throw 'Previous role does not match the saved local application credential.' }
        $oldExists = Invoke-Database $AdminUser $adminPassword 'postgres' "SELECT count(*) FROM pg_roles WHERE rolname='$PreviousAppRole';"
        if ($exists -ne '0' -and $oldExists -ne '0') { throw 'Both application roles already exist; neither was changed.' }
        $appPassword = [Uri]::UnescapeDataString($previousParts[1])
        if ($exists -eq '0' -and $oldExists -ne '0') {
            $owned = Invoke-Database $AdminUser $adminPassword 'postgres' "SELECT count(*) FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='$PreviousAppRole');"
            if ($owned -ne '0') { throw 'Previous role still owns a database; it was not renamed.' }
            $null = Invoke-Database $PreviousAppRole $appPassword 'postgres' 'SELECT 1;'
            $null = Invoke-Database $AdminUser $adminPassword 'postgres' "ALTER ROLE $PreviousAppRole RENAME TO $AppRole;"
            $exists = '1'
        } elseif ($exists -eq '0') { throw 'Previous application role no longer exists.' }
    }
    if ($exists -eq '0') {
        $appPassword = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)).ToLowerInvariant()
        $null = Invoke-Database $AdminUser $adminPassword 'postgres' "CREATE ROLE $AppRole LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '$appPassword';"
    } else {
        $stored = [Environment]::GetEnvironmentVariable('GONET_DATABASE_URL', 'User')
        if ($stored -and -not $appPassword) {
            try {
                $parsed = [Uri]$stored
                $parts = $parsed.UserInfo.Split(':', 2)
                if ($parsed.Host -eq '127.0.0.1' -and $parsed.Port -eq 5432 -and [Uri]::UnescapeDataString($parts[0]) -eq $AppRole -and $parts.Length -eq 2) {
                    $appPassword = [Uri]::UnescapeDataString($parts[1])
                }
            } catch { $appPassword = $null }
        }
        if (-not $appPassword) { $appPassword = Read-LocalPassword "Existing password for application role $AppRole (will not reset it)" }
    }
    if (-not $owner) { $null = Invoke-Database $AdminUser $adminPassword 'postgres' "CREATE DATABASE $DatabaseName OWNER $AppRole;" }
    $null = Invoke-Database $AppRole $appPassword $DatabaseName 'SELECT 1;'
    $dsn = 'postgresql://' + $AppRole + ':' + [Uri]::EscapeDataString($appPassword) + '@127.0.0.1:5432/' + $DatabaseName + '?sslmode=disable'
    # Only local loopback development is configured here. Remote production
    # connections require verify-full and the operator's CA configuration.
    [Environment]::SetEnvironmentVariable('GONET_DATABASE_URL', $dsn, 'User')
    $env:GONET_DATABASE_URL = $dsn
    if (-not (Test-Path -LiteralPath $configPath)) { Copy-Item -LiteralPath (Join-Path $root 'config\config.example.yaml') -Destination $configPath }

    Write-State 'migrating' 'Applying GoNet migrations and verifying export with the application role.'
    Push-Location $root
    try {
        $binary = Join-Path $root '.tools\gonet-service.exe'
        if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $root '.gocache' }
        go build -o $binary ./cmd/gonet
        if ($LASTEXITCODE -ne 0) { throw 'GoNet build failed; database environment variable has already been saved.' }
        & $binary migrate up --config $configPath
        if ($LASTEXITCODE -ne 0) { throw 'GoNet migration failed. No test suite was run against the application database.' }
        & $binary topology export --config $configPath --state all --output -
        if ($LASTEXITCODE -ne 0) { throw 'GoNet topology export failed.' }
    } finally { Pop-Location }
    Write-State 'complete' 'Service on 5432 ready; test instance removed; GONET_DATABASE_URL saved for the current Windows user; migrations and export passed.'
    Write-Host "Ready: 127.0.0.1:5432 / $DatabaseName / $AppRole" -ForegroundColor Green
    Write-Host "GoNet config: $configPath"
    Write-Host 'Connection: Windows USER environment variable GONET_DATABASE_URL. New terminals read it automatically.'
    Write-Host 'Do not set GONET_TEST_DATABASE_URL to this application database.'
} catch {
    Write-State 'error' $_.Exception.Message
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host 'Passwords were not printed or written to YAML. Existing administrator password was not changed.'
    exit 1
} finally { $adminPassword = $null; $appPassword = $null }
