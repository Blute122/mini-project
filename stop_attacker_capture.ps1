$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$etl = Join-Path $root 'attacker_capture.etl'
$txt = Join-Path $root 'attacker_capture.txt'

Write-Host 'Stopping attacker capture...'
pktmon stop

Write-Host 'Converting ETL to text...'
pktmon etl2txt $etl --out $txt --verbose --hex --timestamp

Write-Host ''
Write-Host 'Searching capture for known plaintext markers...'
$patterns = @(
    'ATTACKER_SHOULD_NOT_SEE_THIS_123',
    'TOP_SECRET_PANEL_FILE',
    'Rufrone panel demo confidential file payload'
)

$matches = Select-String -Path $txt -Pattern $patterns -SimpleMatch

if ($matches) {
    Write-Host 'WARNING: Found plaintext markers in capture:' -ForegroundColor Red
    $matches | ForEach-Object { Write-Host $_.Line }
} else {
    Write-Host 'PASS: No known plaintext markers found in captured transport traffic.' -ForegroundColor Green
}

Write-Host ''
Write-Host "Capture text saved to: $txt"
