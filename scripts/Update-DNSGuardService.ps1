[CmdletBinding()]
param(
    [string]$Executable,
    [switch]$Preview
)
$ErrorActionPreference = 'Stop'
if (-not $Executable) { $Executable = Join-Path $PSScriptRoot '..\build\Release\dns_guard.exe' }
$source = (Resolve-Path -LiteralPath $Executable).Path
$directory = Join-Path $env:ProgramFiles 'RogerfabDNSGuard'
$binary = Join-Path $directory 'dns_guard.exe'
$config = Join-Path $directory 'config\loopback.conf'
if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
    -not (Test-Path -LiteralPath $binary -PathType Leaf) -or
    -not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw 'Source binary or installed service files are missing.'
}
$service = Get-Service -Name RogerfabDNSGuard -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'RogerfabDNSGuard must be running before this upgrade.' }
$command = (sc.exe qc RogerfabDNSGuard) -join "`n"
if ($LASTEXITCODE -ne 0 -or
    $command.IndexOf($binary,[StringComparison]::OrdinalIgnoreCase) -lt 0 -or
    $command.IndexOf($config,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw 'Installed service does not reference the expected binary and config.'
}
$settings = Get-Content -LiteralPath $config -Raw
if ($settings -match '(?m)^\s*listen_ipv6_port\s*=') { throw 'Installed config already sets listen_ipv6_port.' }
if ($settings -notmatch '(?m)^\s*listen_ipv4\s*=\s*127\.0\.0\.1\s*$' -or
    $settings -notmatch '(?m)^\s*listen_port\s*=\s*5354\s*$') {
    throw 'Installed config does not use the expected IPv4 loopback listener.'
}
if (Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue |
    Where-Object LocalAddress -EQ '::1') { throw 'IPv6 UDP port 53 is already in use.' }
if (Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue |
    Where-Object LocalAddress -EQ '::1') { throw 'IPv6 TCP port 53 is already in use.' }
Write-Host "Source: $source"
Write-Host "Installed binary: $binary"
Write-Host "Config: $config (append listen_ipv6_port=53; retain other settings)"
if ($Preview) { Write-Host 'Preview only; no files or service changed.'; return }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in Administrator PowerShell.'
}
$backup = Join-Path $directory ('rollback-' + [guid]::NewGuid().ToString('N'))
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
New-Item -ItemType Directory -Path $backup -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $backup 'dns_guard.exe') -ErrorAction Stop
Copy-Item -LiteralPath $config -Destination (Join-Path $backup 'loopback.conf') -ErrorAction Stop
Write-Host "Rollback files: $backup"
$stopping = $false
try {
    $stopping = $true
    Stop-Service -Name RogerfabDNSGuard -ErrorAction Stop
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    Copy-Item -LiteralPath $source -Destination $binary -Force -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $sourceHash) {
        throw 'Installed binary differs from the verified source.'
    }
    Add-Content -LiteralPath $config -Value "`nlisten_ipv6_port=53" -ErrorAction Stop
    Start-Service -Name RogerfabDNSGuard -ErrorAction Stop
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    $probe = Join-Path $PSScriptRoot 'Test-DNSGuard.ps1'
    foreach ($server in '127.0.0.1','::1') {
        $port = if ($server -eq '::1') { 53 } else { 5354 }
        foreach ($tcp in $false,$true) {
            $blocked = & $probe -Server $server -Port $port -Name blocked.example -Tcp:$tcp
            $allowed = & $probe -Server $server -Port $port -Name example.com -Tcp:$tcp
            if ($blocked.Status -ne 'REFUSED' -or $allowed.Status -ne 'NOERROR' -or $allowed.Answers -lt 1) {
                throw "Block/allow verification failed on $server`:$port (TCP=$tcp)."
            }
        }
    }
    Write-Host 'Service upgrade verified: IPv4/IPv6 UDP/TCP block and allow passed.'
} catch {
    $failure = $_.Exception.Message
    if ($stopping) {
        try {
            Stop-Service -Name RogerfabDNSGuard -ErrorAction SilentlyContinue
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
            Copy-Item -LiteralPath (Join-Path $backup 'dns_guard.exe') -Destination $binary -Force -ErrorAction Stop
            Copy-Item -LiteralPath (Join-Path $backup 'loopback.conf') -Destination $config -Force -ErrorAction Stop
            Start-Service -Name RogerfabDNSGuard -ErrorAction Stop
            $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
            Write-Host 'Previous binary and config restored; old service is running.'
        } catch {
            throw "Upgrade failed: $failure. Automatic rollback failed: $($_.Exception.Message). Restore files from $backup manually."
        }
    }
    throw "Upgrade failed: $failure. Previous service restored; files remain at $backup."
}
