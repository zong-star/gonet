param(
    [ValidateRange(1, 1440)][int]$EveryMinutes = 15,
    [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$TaskName = 'GoNet-Scan',
    [switch]$Preview
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$runner = Join-Path $PSScriptRoot 'scan.ps1'
$engine = (Get-Command pwsh -ErrorAction Stop).Source
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -File "' + $runner + '" -Quiet'
if ($Preview) {
    @{ task = $TaskName; every_minutes = $EveryMinutes; user = $user; executable = $engine
       arguments = $arguments; working_directory = $root; logon = 'Interactive'; registered = $false } | ConvertTo-Json
    exit 0
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw "Task '$TaskName' already exists; no changes made."
}
$action = New-ScheduledTaskAction -Execute $engine -Argument $arguments -WorkingDirectory $root
$triggers = @(
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval ([TimeSpan]::FromMinutes($EveryMinutes))),
    (New-ScheduledTaskTrigger -AtLogOn -User $user)
)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromMinutes(20)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'GoNet: read-only recursive discovery and PostgreSQL topology export.' | Select-Object TaskName, State
Write-Host ("已创建 {0}：每 {1} 分钟运行，当前用户登录且电脑唤醒时执行。" -f $TaskName, $EveryMinutes)
