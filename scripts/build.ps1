param([ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.+_-]*$')][string]$Version = '0.13.0-dev')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $root "dist\$Version"
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$oldGOOS, $oldGOARCH, $oldCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
$oldGOTMP = $env:GOTMPDIR
Push-Location $root
try {
    if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $root '.gocache' }
    if (-not $env:GOTMPDIR) { $env:GOTMPDIR = Join-Path $root '.tools/tmp/build' }
    New-Item -ItemType Directory -Path $env:GOTMPDIR -Force | Out-Null
    $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    foreach ($platform in @('windows', 'linux')) {
        $env:GOOS = $platform
        $packagePath = Join-Path $outputPath "$platform-amd64"
        # This is a generated staging directory. Recreate it so deleted or newly
        # excluded evidence cannot survive from an earlier package build.
        if(Test-Path -LiteralPath $packagePath){
            $target=(Resolve-Path -LiteralPath $packagePath).Path
            $boundary=(Resolve-Path -LiteralPath $outputPath).Path
            if((Split-Path -Parent $target) -ne $boundary -or (Split-Path -Leaf $target) -ne "$platform-amd64"){throw 'Unsafe package staging path'}
            Remove-Item -LiteralPath $target -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $packagePath | Out-Null
        $binaryName = if ($platform -eq 'windows') { 'gonet.exe' } else { 'gonet' }
        go build -trimpath -buildvcs=false -ldflags "-X gonet/internal/cli.Version=$Version" -o (Join-Path $packagePath $binaryName) ./cmd/gonet
        if ($LASTEXITCODE -ne 0) { throw "Build $platform failed" }
        Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination $packagePath -Force
        # Deliver documentation/evidence, excluding machine-local configuration
        # copies, API snapshots, process records and browser runtime profiles.
        $docsRoot=Join-Path $root 'docs'
        foreach($file in Get-ChildItem -LiteralPath $docsRoot -File -Recurse){
            $relative=[IO.Path]::GetRelativePath($docsRoot,$file.FullName)
            if($relative -match '(^|[\\/])(backup|server-fixture|chrome-profile[^\\/]*)([\\/]|$)' -or
               $file.Name -match '^(api-state|state-before|state-after|process-before|process-after|sample-state)\.json$' -or
               $file.Name -in @('package-checks.json','browser-failure.json') -or $file.Name -like '*.log'){continue}
            $target=Join-Path (Join-Path $packagePath 'docs') $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force|Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        }
        Copy-Item -LiteralPath (Join-Path $root 'deploy') -Destination $packagePath -Recurse -Force
        $configDirectory=Join-Path $packagePath 'config'
        New-Item -ItemType Directory -Force -Path $configDirectory | Out-Null
        foreach($name in @('config.example.yaml','device_rules.yaml','port_rules.yaml')){Copy-Item -LiteralPath (Join-Path $root ('config\'+$name)) -Destination $configDirectory -Force}
        if ($platform -eq 'windows') {
            $scriptDirectory = Join-Path $packagePath 'scripts'
            New-Item -ItemType Directory -Force -Path $scriptDirectory | Out-Null
            foreach ($name in @('start-ui.ps1','stop-ui.ps1','scan.ps1','show-topology.ps1','draw-topology.ps1','draw-core-topology.ps1','topology-scope.ps1','register-scan-task.ps1')) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $scriptDirectory -Force }
        }
        $archivePath = Join-Path $outputPath "gonet-$Version-$platform-amd64.zip"
        Compress-Archive -Path (Join-Path $packagePath '*') -DestinationPath $archivePath -Force
    }
    $hashLines = Get-ChildItem -LiteralPath $outputPath -Filter '*.zip' | Sort-Object Name | ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        "$($hash.Hash.ToLowerInvariant())  $($_.Name)"
    }
    $hashLines | Set-Content -LiteralPath (Join-Path $outputPath 'SHA256SUMS') -Encoding ascii
    $hashLines
} finally {
    $env:GOOS = $oldGOOS; $env:GOARCH = $oldGOARCH; $env:CGO_ENABLED = $oldCGO
    $env:GOTMPDIR = $oldGOTMP
    Pop-Location
}
