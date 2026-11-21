[CmdletBinding()]
param([switch]$Preview)
$ErrorActionPreference = 'Stop'
$rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {
    $_.DisplayName -like 'RogerfabDNSGuardPolicy-*' -and
    @($_.Namespace) -contains '.'
})
if (-not $rules.Count) { Write-Host 'No persistent DNS Guard NRPT rule found.'; return }
if ($rules.Count -ne 1) { throw 'Multiple DNS Guard rules found; inspect before removing.' }
Write-Host "DNS Guard NRPT rule: $($rules[0].Name)"
if ($Preview) { Write-Host 'Preview only; no DNS policy changed.'; return }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in Administrator PowerShell.'
}
Remove-DnsClientNrptRule -Name $rules[0].Name -Force -ErrorAction Stop
if (Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Name -eq $rules[0].Name }) {
    throw 'DNS Guard rule removal could not be verified.'
}
Clear-DnsClientCache
Write-Host 'Persistent DNS Guard rule removed; adapter DNS settings were not changed.'
