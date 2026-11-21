[CmdletBinding()]
param([switch]$Preview, [switch]$Persist)
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name RogerfabDNSGuard -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'DNS Guard service is not running.' }
if ($Persist -and $service.StartType -ne 'Automatic') {
    throw 'Persistent policy requires automatic service startup.'
}
if ($Persist) {
    $recovery = (sc.exe qfailure RogerfabDNSGuard) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $recovery -notmatch 'RESTART') {
        throw 'Persistent policy requires configured service restart-on-failure actions.'
    }
}
if (@(Get-DnsClientNrptRule -ErrorAction Stop).Count) {
    throw 'Existing NRPT rules found; this trial requires an empty NRPT table.'
}
$probe = Join-Path $PSScriptRoot 'Test-DNSGuard.ps1'
$blocked = & $probe -Server '::1' -Port 53 -Name blocked.example
$allowed = & $probe -Server '::1' -Port 53 -Name example.com
if ($blocked.Status -ne 'REFUSED' -or $allowed.Status -ne 'NOERROR' -or $allowed.Answers -lt 1) {
    throw 'Direct DNS Guard block/allow check failed.'
}
foreach ($name in 'example.com','example.org') {
    if (-not @(Resolve-DnsName $name -Type A -ErrorAction Stop | Where-Object { $_.IPAddress }).Count) {
        throw "Windows DNS baseline failed for $name."
    }
}
Write-Host 'Preflight passed: Guard and ordinary Windows DNS work.'
Write-Host "Proposed $(if ($Persist) { 'persistent' } else { 'temporary' }) NRPT rule: namespace . (all ordinary Windows DNS names) -> ::1."
if ($Persist) { Write-Warning 'If the Guard service stops, ordinary Windows DNS may fail until this rule is removed.' }
if ($Preview) { Write-Host 'Preview only; no DNS policy changed.'; return }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this trial in Administrator PowerShell.'
}
$expected = if ($Persist) { 'PERSIST' } else { 'YES' }
$prompt = if ($Persist) { 'Type PERSIST to keep all-domain routing enabled' } else { 'Type YES for a temporary all-domain trial' }
if ((Read-Host $prompt) -ne $expected) {
    Write-Host 'No Windows DNS policy changed.'
    return
}
$display = $(if ($Persist) { 'RogerfabDNSGuardPolicy-' } else { 'RogerfabDNSGuardAllDomainTrial-' }) +
    [guid]::NewGuid().ToString('N')
Write-Host "DNS Guard rule identity: $display"
$verified = $false
try {
    $rule = Add-DnsClientNrptRule -Namespace '.' -NameServers '::1' `
        -DisplayName $display -PassThru -ErrorAction Stop
    Write-Host "NRPT rule: $($rule.Name)"
    Clear-DnsClientCache
    $effective = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object {
        @($_.Namespace) -contains '.' -and @($_.NameServers) -contains '::1'
    })
    if (-not $effective.Count) { throw 'All-domain NRPT policy was not effective.' }
    foreach ($name in 'example.com','example.org') {
        if (-not @(Resolve-DnsName $name -Type A -ErrorAction Stop | Where-Object { $_.IPAddress }).Count) {
            throw "Allowed Windows DNS lookup failed for $name."
        }
    }
    $lookupErrors = @()
    $denied = @(Resolve-DnsName blocked.example -Type A -ErrorAction SilentlyContinue -ErrorVariable +lookupErrors |
        Where-Object { $_.IPAddress })
    if ($denied.Count -or -not $lookupErrors.Count -or
        $lookupErrors[0].FullyQualifiedErrorId -notlike 'RCODE_REFUSED,*') {
        throw 'Blocked domain did not produce DNS RCODE_REFUSED.'
    }
    Write-Host "Blocked lookup error: $($lookupErrors[0].FullyQualifiedErrorId)"
    $verified = $true
    Write-Host 'All-domain policy verified: allowed names resolved and blocked.example returned REFUSED.'
    if ($Persist) { Write-Host "Policy remains enabled. Emergency rollback: Remove-DnsClientNrptRule -Name '$($rule.Name)' -Force; Clear-DnsClientCache" }
} finally {
    if (-not $Persist -or -not $verified) {
        $trialRules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object DisplayName -EQ $display)
        foreach ($trialRule in $trialRules) {
            Remove-DnsClientNrptRule -Name $trialRule.Name -Force -ErrorAction Stop
        }
        if (Get-DnsClientNrptRule -ErrorAction Stop | Where-Object DisplayName -EQ $display) {
            throw "Rollback failed: remove only trial rule $display before further DNS changes."
        }
        Clear-DnsClientCache
        Write-Host 'Temporary all-domain rule removed.'
        if (-not @(Resolve-DnsName example.com -Type A -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress }).Count) {
            throw 'Rule removed, but ordinary Windows DNS resolution did not recover.'
        }
        Write-Host 'Ordinary Windows DNS resolution restored.'
    }
}
