param([switch]$Demo)
$ErrorActionPreference='Stop'
Set-Location $PSScriptRoot
if (-not $Demo -and -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env.local'))) { throw 'Configure Entra .env.local first, or explicitly use -Demo.' }
foreach ($tool in @('.venv/Scripts/python.exe','.tools/node_modules/azure-functions-core-tools/bin/func.exe','.tools/node_modules/azurite/dist/src/azurite.js')) {
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $tool))) { throw "Missing local tool: $tool. See LOCAL_FUNCTIONS.md." }
}
foreach ($port in @(10000,10001,10002,7071,8765)) {
    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) { throw "Port $port is already in use. Stop the recorded local stack first." }
}
$python=Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
$setupArgs=@((Join-Path $PSScriptRoot 'scripts/setup-functions-local.py'))
if ($Demo) { $setupArgs += '--demo' }
& $python @setupArgs
if ($LASTEXITCODE -ne 0) { throw 'Local configuration failed' }
$logRoot=Join-Path $PSScriptRoot '.functions-log'
New-Item -ItemType Directory -Force $logRoot | Out-Null
$running=@()
foreach ($entry in @(@('storage','run-storage.ps1'),@('functions','run-functions.ps1'),@('ui','run-local.ps1'))) {
    $scriptPath=Join-Path $PSScriptRoot $entry[1]
    $processArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$scriptPath+'"'))
    if ($Demo -and $entry[0] -eq 'ui') { $processArgs += '-Demo' }
    $process=Start-Process powershell.exe -WindowStyle Hidden -PassThru -WorkingDirectory $PSScriptRoot -ArgumentList $processArgs -RedirectStandardOutput (Join-Path $logRoot ($entry[0]+'.out.log')) -RedirectStandardError (Join-Path $logRoot ($entry[0]+'.err.log'))
    $running+=@{name=$entry[0];pid=$process.Id;script=$scriptPath}
    $running | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot '.data/stack-processes.json')
    if ($entry[0] -eq 'functions') {
        $deadline=(Get-Date).AddSeconds(90)
        $ready=$false
        while ((Get-Date) -lt $deadline) {
            try { $health=Invoke-RestMethod -Uri 'http://127.0.0.1:7071/health' -TimeoutSec 2; if ($health.publisher -eq 'mock') { $ready=$true; break } } catch {}
            Start-Sleep -Seconds 1
        }
        if (-not $ready) { throw 'Function startup timed out. See .functions-log and run stop-stack.ps1 before retrying.' }
    }
}
$running | ConvertTo-Json | Set-Content (Join-Path $PSScriptRoot '.data/stack-processes.json')
Write-Host 'Local stack ready: http://localhost:8765 (Entra UI) / http://127.0.0.1:7071 (Functions)'
Write-Host 'Stop with: ./stop-stack.ps1. Logs: .functions-log'
