$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$etl = Join-Path $root 'attacker_capture.etl'
$txt = Join-Path $root 'attacker_capture.txt'

Write-Host 'Starting attacker capture for UDP relay traffic on ports 9001 <-> 9002'
Write-Host 'Run this PowerShell as Administrator for best results.'

try { pktmon stop | Out-Null } catch { }
try { pktmon unload | Out-Null } catch { }
try { pktmon filter remove | Out-Null } catch { }

if (Test-Path $etl) { Remove-Item $etl -Force }
if (Test-Path $txt) { Remove-Item $txt -Force }

pktmon filter add RufroneRelay -t UDP -p 9001 9002
pktmon start --capture --pkt-size 0 --file-name $etl

Write-Host ''
Write-Host 'Capture started.'
Write-Host 'Now do the following in the demo:'
Write-Host '  1. Send chat message: ATTACKER_SHOULD_NOT_SEE_THIS_123'
Write-Host '  2. Send file: TOP_SECRET_PANEL_FILE.txt'
Write-Host '  3. Then run .\stop_attacker_capture.ps1'
