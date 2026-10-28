param([int]$Port = 8765, [switch]$Demo)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$localPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $localPython)) { throw 'Python 가상환경을 먼저 설치해 주세요.' }
Write-Host "USB 운영 콘솔: http://localhost:$Port"
$serverArgs = @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port',"$Port",'--no-access-log')
if ($Demo) { $env:USB_AUTH_MODE = 'demo' }
elseif (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env.local')) { $env:USB_AUTH_MODE = 'entra'; $serverArgs += @('--env-file', (Join-Path $PSScriptRoot '.env.local')) }
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot '.env.functions')) {
    $bridgeEnv=Join-Path $PSScriptRoot '.env.functions'
    & $localPython -m dotenv --file $bridgeEnv run --no-override -- $localPython @serverArgs
} else {
    & $localPython @serverArgs
}