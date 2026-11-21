#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$Config
)
$ErrorActionPreference = 'Stop'
$binary = (Resolve-Path -LiteralPath $Executable).Path
$configFile = (Resolve-Path -LiteralPath $Config).Path
if ((Get-Item -LiteralPath $binary).PSIsContainer -or
    (Get-Item -LiteralPath $configFile).PSIsContainer) {
    throw 'Executable and Config must be files.'
}
if (Get-Service -Name RogerfabDNSGuard -ErrorAction SilentlyContinue) {
    throw 'RogerfabDNSGuard is already installed. Stop and remove it before reinstalling.'
}
$command = '"' + $binary + '" "' + $configFile + '" --service'
if ($PSCmdlet.ShouldProcess('RogerfabDNSGuard', 'Install manual-start service as LocalService')) {
    $account = [PSCredential]::new('NT AUTHORITY\LocalService', [Security.SecureString]::new())
    New-Service -Name RogerfabDNSGuard -BinaryPathName $command -StartupType Manual -Credential $account | Out-Null
    Write-Host 'Installed. Start-Service RogerfabDNSGuard starts it; Stop-Service RogerfabDNSGuard stops it.'
    Write-Host 'Use a trusted deployment directory and grant LocalService read access to configuration and lists.'
}
