$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$flag = Join-Path $root 'attack_capture.enabled'
$log = Join-Path $root 'attack_capture.ndjson'

if (Test-Path $flag) {
    Remove-Item $flag -Force
}

Write-Host 'Passive transport capture disabled.'
Write-Host ''

if (-not (Test-Path $log)) {
    Write-Host "No capture log found at $log" -ForegroundColor Red
    exit 1
}

python (Join-Path $root 'analyze_attack_capture.py') --log $log

Write-Host ''
Write-Host "Capture log saved to: $log"
