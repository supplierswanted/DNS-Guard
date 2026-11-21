#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name RogerfabDNSGuard -ErrorAction Stop
if ($PSCmdlet.ShouldProcess('RogerfabDNSGuard', 'Stop and remove Windows service')) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name RogerfabDNSGuard -ErrorAction Stop
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    $service.Dispose()
    & sc.exe delete RogerfabDNSGuard
    if ($LASTEXITCODE -ne 0) { throw "Service removal failed ($LASTEXITCODE)." }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ((Get-Service -Name RogerfabDNSGuard -ErrorAction SilentlyContinue) -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Get-Service -Name RogerfabDNSGuard -ErrorAction SilentlyContinue) {
        throw 'Windows has not released the service registration.'
    }
}
