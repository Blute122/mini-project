$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$flag = Join-Path $root 'attack_capture.enabled'
$log = Join-Path $root 'attack_capture.ndjson'

if (Test-Path $log) { Remove-Item $log -Force }
Set-Content -Path $flag -Value 'enabled' -Encoding ascii

Write-Host ''
Write-Host 'Passive transport capture enabled.'
Write-Host 'This records raw relay-path datagrams as seen by the blind transport layer.'
Write-Host 'Restart is NOT required if the daemons are already running.'
Write-Host 'Now do the following in the demo:'
Write-Host '  1. Send chat message: ATTACKER_SHOULD_NOT_SEE_THIS_123'
Write-Host '  2. Send file: TOP_SECRET_PANEL_FILE.txt'
Write-Host '  3. Then run .\stop_attacker_capture.ps1'
