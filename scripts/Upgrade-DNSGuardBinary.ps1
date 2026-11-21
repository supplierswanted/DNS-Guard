[CmdletBinding()]
param([switch]$Preview)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\build\Release\dns_guard.exe')).Path
$directory = Join-Path $env:ProgramFiles 'RogerfabDNSGuard'
$binary = Join-Path $directory 'dns_guard.exe'
$config = Join-Path $directory 'config\loopback.conf'
$feed = Join-Path $directory 'config\feed.txt'
foreach ($file in @($binary,$config,$feed)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Installed file missing: $file" }
}
$settings = Get-Content -LiteralPath $config -Raw
if ($settings -notmatch '(?m)^\s*listen_ipv4\s*=\s*127\.0\.0\.1\s*$' -or
    $settings -notmatch '(?m)^\s*listen_port\s*=\s*5354\s*$' -or
    $settings -notmatch '(?m)^\s*listen_ipv6_port\s*=\s*53\s*$' -or
    $settings -notmatch '(?m)^\s*feedlist\s*=\s*feed\.txt\s*$') {
    throw 'Installed configuration differs from the verified loopback setup.'
}
$service = Get-Service RogerfabDNSGuard -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'DNS Guard must be running before upgrade.' }
$command = (sc.exe qc RogerfabDNSGuard) -join "`n"
if ($LASTEXITCODE -ne 0 -or
    $command.IndexOf($binary,[StringComparison]::OrdinalIgnoreCase) -lt 0 -or
    $command.IndexOf($config,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw 'Service references unexpected files.'
}
$oldHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
$newHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
Write-Host "Installed: $oldHash"
Write-Host "Candidate: $newHash"
if ($oldHash -eq $newHash) { Write-Host 'Already current; nothing changed.'; return }
Write-Warning 'The active DNS policy can cause a brief DNS interruption during service restart.'
if ($Preview) { Write-Host 'Preview only; service and DNS policy unchanged.'; return }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in Administrator PowerShell.' }
$backup = Join-Path $directory ('rollback-binary-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backup -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $backup 'dns_guard.exe') -ErrorAction Stop
$stopping = $false
try {
    $stopping = $true
    Stop-Service RogerfabDNSGuard -ErrorAction Stop
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    Copy-Item -LiteralPath $source -Destination $binary -Force -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $newHash) {
        throw 'Copied binary hash differs from candidate.'
    }
    Start-Service RogerfabDNSGuard -ErrorAction Stop
    $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    $probe = Join-Path $PSScriptRoot 'Test-DNSGuard.ps1'
    $feedDomain = Get-Content -LiteralPath $feed -TotalCount 1
    if (-not $feedDomain) { throw 'Feed is empty.' }
    foreach ($server in @('127.0.0.1','::1')) {
        $port = if ($server -eq '::1') { 53 } else { 5354 }
        foreach ($tcp in @($false,$true)) {
            $manual = & $probe -Server $server -Port $port -Name blocked.example -Tcp:$tcp
            $denied = & $probe -Server $server -Port $port -Name $feedDomain -Tcp:$tcp
            $allowed = & $probe -Server $server -Port $port -Name example.com -Tcp:$tcp
            if ($manual.Status -ne 'REFUSED' -or $denied.Status -ne 'REFUSED' -or
                $allowed.Status -ne 'NOERROR' -or $allowed.Answers -lt 1) {
                throw "DNS verification failed on $server`:$port (TCP=$tcp)."
            }
        }
    }
    Write-Host 'New binary verified over IPv4/IPv6 UDP/TCP; upstream, feed and DNS policy unchanged.'
    Write-Host "Rollback binary: $backup\dns_guard.exe"
} catch {
    $failure = $_.Exception.Message
    if ($stopping) {
        try {
            Stop-Service RogerfabDNSGuard -ErrorAction SilentlyContinue
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
            Copy-Item -LiteralPath (Join-Path $backup 'dns_guard.exe') -Destination $binary -Force -ErrorAction Stop
            Start-Service RogerfabDNSGuard -ErrorAction Stop
            $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        } catch { throw "Upgrade failed: $failure. Rollback failed: $($_.Exception.Message). Backup: $backup" }
    }
    throw "Upgrade failed: $failure. Previous binary restored. Backup: $backup"
}
