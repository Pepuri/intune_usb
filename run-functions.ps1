$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$env:VIRTUAL_ENV = Join-Path $PSScriptRoot '.venv'
$env:PATH = (Join-Path $PSScriptRoot '.venv/Scripts') + ';' + $env:PATH
$funcExe = Join-Path $PSScriptRoot '.tools/node_modules/azure-functions-core-tools/bin/func.exe'
if (-not (Test-Path -LiteralPath $funcExe)) { throw 'Install local tools first: npm.cmd install --prefix .tools azure-functions-core-tools@4 azurite' }
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'local.settings.json'))) { throw 'Run scripts/setup-functions-local.py first.' }
& $funcExe start --address 127.0.0.1 --port 7071 --timeout 90
