$ErrorActionPreference='Stop'
$record=Join-Path $PSScriptRoot '.data/stack-processes.json'
if (-not (Test-Path -LiteralPath $record)) { Write-Host 'No recorded local stack.'; exit 0 }
$entries=Get-Content -LiteralPath $record -Raw | ConvertFrom-Json
function Stop-OwnedTree([int]$taskProcessId) {
    $children=Get-CimInstance Win32_Process -Filter "ParentProcessId=$taskProcessId"
    foreach ($child in $children) { Stop-OwnedTree $child.ProcessId }
    Stop-Process -Id $taskProcessId -ErrorAction SilentlyContinue
}
foreach ($entry in @($entries) | Sort-Object -Property name -Descending) {
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($entry.pid)"
    if ($process -and $process.CommandLine -and $process.CommandLine.IndexOf($PSScriptRoot,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Stop-OwnedTree $process.ProcessId
        Write-Host "Stopped local $($entry.name)."
    }
}
