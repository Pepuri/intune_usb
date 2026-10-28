$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$azuriteScript = Join-Path $PSScriptRoot '.tools/node_modules/azurite/dist/src/azurite.js'
$location = Join-Path $PSScriptRoot '.data/azurite'
New-Item -ItemType Directory -Force $location | Out-Null
& node $azuriteScript --silent --skipApiVersionCheck --location $location --blobHost 127.0.0.1 --queueHost 127.0.0.1 --tableHost 127.0.0.1
