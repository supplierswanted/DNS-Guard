[CmdletBinding()]
param([switch]$Preview)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$source = Join-Path $root 'build\Release\dns_guard.exe'
$updaterSource = Join-Path $PSScriptRoot 'Update-DNSBlocklist.ps1'
$installed = Join-Path $env:ProgramFiles 'RogerfabDNSGuard'
$binary = Join-Path $installed 'dns_guard.exe'
$config = Join-Path $installed 'config\loopback.conf'
$feed = Join-Path $installed 'config\feed.txt'
$updater = Join-Path $installed 'Update-DNSBlocklist.ps1'
$taskName = 'RogerfabDNSGuardBlocklistUpdate'
foreach ($file in @($source, $updaterSource, $binary, $config)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing file: $file" }
}
if (Test-Path -LiteralPath $updater -PathType Leaf) { throw 'Installed updater already exists; inspect it before replacing.' }
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'Blocklist update task already exists; inspect it before replacing.'
}
$service = Get-Service RogerfabDNSGuard -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'DNS Guard service must be running.' }
$settings = Get-Content -LiteralPath $config -Raw
if ($settings -notmatch '(?m)^\s*listen_ipv4\s*=\s*127\.0\.0\.1\s*$' -or
    $settings -notmatch '(?m)^\s*listen_port\s*=\s*5354\s*$' -or
    $settings -notmatch '(?m)^\s*listen_ipv6_port\s*=\s*53\s*$') {
    throw 'Installed loopback listener differs from the verified configuration.'
}
if ($settings -match '(?m)^\s*feedlist\s*=') { throw 'Feedlist is already configured; inspect it before deployment.' }
$command = (sc.exe qc RogerfabDNSGuard) -join "`n"
if ($LASTEXITCODE -ne 0 -or
    $command.IndexOf($binary, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
    $command.IndexOf($config, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw 'Service path differs from the expected installation.'
}
Write-Host "Binary: $source -> $binary"
Write-Host "Feed: $feed (daily HTTPS update at 03:00)"
Write-Host "Upstream and Windows DNS policy will remain unchanged."
if ($Preview) { Write-Host 'Preview only; nothing changed.'; return }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in Administrator PowerShell.' }

$backup = Join-Path $installed ('rollback-feed-' + [guid]::NewGuid().ToString('N'))
$hadFeed = Test-Path -LiteralPath $feed -PathType Leaf
New-Item -ItemType Directory -Path $backup -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $backup 'dns_guard.exe')
Copy-Item -LiteralPath $config -Destination (Join-Path $backup 'loopback.conf')
if ($hadFeed) { Copy-Item -LiteralPath $feed -Destination (Join-Path $backup 'feed.txt') }
$serviceTouched = $false
$taskCreated = $false
try {
    Copy-Item -LiteralPath $updaterSource -Destination $updater -ErrorAction Stop
    if (-not $hadFeed) { [IO.File]::WriteAllText($feed, '') }
    & $updater -Destination $feed
    $testDomain = Get-Content -LiteralPath $feed -TotalCount 1
    if (-not $testDomain) { throw 'Updated feed is empty.' }
    $serviceTouched = $true
    Stop-Service RogerfabDNSGuard -ErrorAction Stop
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    Copy-Item -LiteralPath $source -Destination $binary -Force -ErrorAction Stop
    if ((Get-FileHash $source -Algorithm SHA256).Hash -ne (Get-FileHash $binary -Algorithm SHA256).Hash) {
        throw 'Installed binary hash differs from source.'
    }
    Add-Content -LiteralPath $config -Value "`nfeedlist=feed.txt" -Encoding ascii
    Start-Service RogerfabDNSGuard -ErrorAction Stop
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $probe = Join-Path $PSScriptRoot 'Test-DNSGuard.ps1'
    foreach ($server in @('127.0.0.1', '::1')) {
        $port = if ($server -eq '::1') { 53 } else { 5354 }
        foreach ($tcp in @($false, $true)) {
            $deny = & $probe -Server $server -Port $port -Name $testDomain -Tcp:$tcp
            $allow = & $probe -Server $server -Port $port -Name example.com -Tcp:$tcp
            if ($deny.Status -ne 'REFUSED' -or $allow.Status -ne 'NOERROR' -or $allow.Answers -lt 1) {
                throw "DNS verification failed on $server`:$port (TCP=$tcp)."
            }
        }
    }
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $updater + '" -Destination "' + $feed + '"')
    $trigger = New-ScheduledTaskTrigger -Daily -At 03:00
    $limits = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $limits `
        -User 'SYSTEM' -ErrorAction Stop | Out-Null
    $taskCreated = $true
    Write-Host "Verified feed block and allowed DNS over IPv4/IPv6 UDP/TCP. Daily task installed."
    Write-Host "Rollback files: $backup"
} catch {
    $failure = $_.Exception.Message
    if ($taskCreated) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    try {
        if ($serviceTouched) {
            Stop-Service RogerfabDNSGuard -ErrorAction SilentlyContinue
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            Copy-Item (Join-Path $backup 'dns_guard.exe') $binary -Force
            Copy-Item (Join-Path $backup 'loopback.conf') $config -Force
        }
        if ($hadFeed) { Copy-Item (Join-Path $backup 'feed.txt') $feed -Force }
        else { Remove-Item -LiteralPath $feed -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $updater -Force -ErrorAction SilentlyContinue
        if ($serviceTouched) {
            Start-Service RogerfabDNSGuard -ErrorAction Stop
            $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
    } catch { throw "Deployment failed: $failure. Rollback also failed: $($_.Exception.Message). Backup: $backup" }
    throw "Deployment failed: $failure. Previous installation restored. Backup: $backup"
}
