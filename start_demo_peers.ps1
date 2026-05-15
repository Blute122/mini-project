$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }

function Start-Peer {
    param(
        [string]$Name,
        [string]$EnvFile
    )

    $envPath = Join-Path $root $EnvFile
    $cmd = @"
Set-Location '$root'
Get-Content '$envPath' | ForEach-Object {
    if (`$_ -match '^\s*#' -or [string]::IsNullOrWhiteSpace(`$_)) { return }
    `$parts = `$_ -split '=', 2
    if (`$parts.Length -eq 2) {
        [Environment]::SetEnvironmentVariable(`$parts[0], `$parts[1], 'Process')
    }
}
& $python rufrone_core.py
Read-Host 'Press Enter to close'
"@

    Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd -WindowStyle Normal
    Write-Host "Started $Name using $EnvFile"
}

Start-Peer -Name 'Peer A' -EnvFile 'demo_peer_a.env'
Start-Peer -Name 'Peer B' -EnvFile 'demo_peer_b.env'

Write-Host ''
Write-Host 'Open these in two browser windows:'
Write-Host '  Peer A: http://localhost:8000/?ws=ws://localhost:8080&peer=Peer-A'
Write-Host '  Peer B: http://localhost:8000/?ws=ws://localhost:8082&peer=Peer-B'
