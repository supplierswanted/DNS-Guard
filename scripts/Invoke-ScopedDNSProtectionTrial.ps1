#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$Executable,
    [string]$BaseConfig
)
$ErrorActionPreference = 'Stop'
if (-not $Executable) { $Executable = Join-Path $PSScriptRoot '..\build\Release\dns_guard.exe' }
if (-not $BaseConfig) { $BaseConfig = Join-Path $PSScriptRoot '..\config\loopback.conf' }
$binary = (Resolve-Path -LiteralPath $Executable).Path
$source = (Resolve-Path -LiteralPath $BaseConfig).Path
$settings = @{}
foreach ($line in Get-Content -LiteralPath $source) {
    $entry = ($line -split '#', 2)[0].Trim()
    if ($entry -match '^([^=]+)=(.*)$') { $settings[$Matches[1].Trim()] = $Matches[2].Trim() }
}
if (-not $settings['upstream_ipv4']) { throw 'Base config has no upstream_ipv4.' }
$upstreamPort = if ($settings['upstream_port']) { $settings['upstream_port'] } else { '53' }
if (Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { @($_.Namespace) -contains 'example.com' }) {
    throw 'An NRPT rule already covers example.com; no trial rule was added.'
}
$trial = Join-Path $env:TEMP ('dns-guard-trial-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $trial -ErrorAction Stop | Out-Null
$trialProcess = $null
$rule = $null
$trialName = 'RogerfabDNSGuardTrial-' + [guid]::NewGuid().ToString('N')
try {
    Set-Content -LiteralPath (Join-Path $trial 'blocked.txt') -Value 'example.com' -Encoding ascii
    Set-Content -LiteralPath (Join-Path $trial 'allowed.txt') -Value '# empty' -Encoding ascii
    $ready = $false
    for ($attempt = 0; $attempt -lt 20 -and -not $ready; $attempt++) {
        $port = Get-Random -Minimum 20000 -Maximum 40000
        @(
            "upstream_ipv4=$($settings['upstream_ipv4'])"
            "upstream_port=$upstreamPort"
            'listen_ipv4=127.0.0.1'
            "listen_port=$port"
            'listen_ipv6_port=53'
            'timeout_ms=2000'
            'workers=4'
            'queue_capacity=64'
            'blocklist=blocked.txt'
            'allowlist=allowed.txt'
        ) | Set-Content -LiteralPath (Join-Path $trial 'trial.conf') -Encoding ascii
        $trialProcess = Start-Process -FilePath $binary -ArgumentList ('"' + (Join-Path $trial 'trial.conf') + '"') `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $trial 'out.txt') `
            -RedirectStandardError (Join-Path $trial 'err.txt')
        Start-Sleep -Milliseconds 500
        $ready = -not $trialProcess.HasExited
        if (-not $ready) { $trialProcess = $null }
    }
    if (-not $ready) { throw 'Trial listener failed to start; inspect port conflicts.' }
    Write-Host "Trial listener PID $($trialProcess.Id) started on [::1]:53."
    $probe = Join-Path $PSScriptRoot 'Test-DNSGuard.ps1'
    $denied = & $probe -Server '::1' -Port 53 -Name 'example.com'
    $allowed = & $probe -Server '::1' -Port 53 -Name 'example.org'
    if ($denied.Status -ne 'REFUSED' -or $allowed.Status -ne 'NOERROR' -or $allowed.Answers -lt 1) {
        throw 'Trial listener failed direct block/allow checks; no Windows DNS policy changed.'
    }
    $baseline = @(Resolve-DnsName example.com -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
    if (-not $baseline.Count) { throw 'Windows DNS baseline failed; no trial rule was added.' }
    Write-Host 'Only example.com will be redirected temporarily.'
    if ((Read-Host 'Type YES to add a temporary Windows DNS policy for example.com') -ne 'YES') {
        Write-Host 'No Windows DNS policy changed.'
        return
    }
    $rule = Add-DnsClientNrptRule -Namespace 'example.com' -NameServers '::1' `
        -DisplayName $trialName -PassThru -ErrorAction Stop
    Write-Host "Temporary NRPT rule: $($rule.Name)"
    Clear-DnsClientCache
    $answer = Resolve-DnsName example.com -Type A -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress }
    if ($answer) { throw 'Windows still resolved example.com; scoped protection failed.' }
    $unaffected = @(Resolve-DnsName example.org -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
    if (-not $unaffected.Count) { throw 'Unrelated Windows DNS resolution failed during trial.' }
    Write-Host 'Windows did not resolve example.com while the trial rule was active; confirm the path with packet capture before claiming full coverage.'
} finally {
    $trialRules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object DisplayName -EQ $trialName)
    foreach ($trialRule in $trialRules) {
        Remove-DnsClientNrptRule -Name $trialRule.Name -Force -ErrorAction Stop
    }
    if (Get-DnsClientNrptRule -ErrorAction Stop | Where-Object DisplayName -EQ $trialName) {
        throw "Rollback could not verify removal of trial rule $trialName; keep the trial listener running."
    }
    $restored = $true
    if ($trialRules.Count) {
        Clear-DnsClientCache
        $restored = @(Resolve-DnsName example.com -Type A -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress }).Count -gt 0
        Write-Host 'Temporary NRPT rule removed; original DNS route restored.'
    }
    if ($trialProcess -and -not $trialProcess.HasExited) {
        Stop-Process -Id $trialProcess.Id -Force -ErrorAction Stop
    }
    if ((Test-Path -LiteralPath $trial) -and
        [IO.Path]::GetFullPath($trial).StartsWith([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
        foreach ($name in 'blocked.txt','allowed.txt','trial.conf','out.txt','err.txt') {
            Remove-Item -LiteralPath (Join-Path $trial $name) -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $trial -Force -ErrorAction SilentlyContinue
    }
    if (-not $restored) { throw 'Trial rule was removed, but Windows DNS resolution did not recover; inspect DNS settings.' }
}
