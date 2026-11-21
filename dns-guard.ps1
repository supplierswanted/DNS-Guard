[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory)]
    [ValidateSet('install','start','stop','status','repair','uninstall')]
    [string]$Action,
    [string]$Config,
    [switch]$BrowserPolicies,
    [switch]$UpdateFeeds
)
$ErrorActionPreference = 'Stop'
$serviceName = 'RogerfabDNSGuard'
$installDir = Join-Path $env:ProgramFiles $serviceName
$binary = Join-Path $installDir 'dns_guard.exe'
$installedConfig = Join-Path $installDir 'config\loopback.conf'
$marker = Join-Path $installDir 'browser-policies.owned'
$updater = Join-Path $installDir 'Update-DNSBlocklist.ps1'
$feed = Join-Path $installDir 'config\feed.txt'
$taskName = 'RogerfabDNSGuardBlocklistUpdate'
$probe = Join-Path $PSScriptRoot 'scripts\Test-DNSGuard.ps1'
$enableRoute = Join-Path $PSScriptRoot 'scripts\Invoke-AllDomainDNSProtectionTrial.ps1'
$disableRoute = Join-Path $PSScriptRoot 'scripts\Disable-DNSGuardPolicy.ps1'
$policies = @(
    @{ Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DnsOverHttpsMode'; Value='off'; Type='String' },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DnsOverHttpsMode'; Value='off'; Type='String' },
    @{ Path='HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name='Enabled'; Value=0; Type='DWord' },
    @{ Path='HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name='Locked'; Value=1; Type='DWord' }
)

function Test-Administrator {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Require-Administrator {
    if (-not (Test-Administrator)) {
        throw 'Run this command in Administrator PowerShell.'
    }
}
function Guard-Rules {
    @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {
        $_.DisplayName -like 'RogerfabDNSGuardPolicy-*' -and @($_.Namespace) -contains '.'
    })
}
function Assert-DirectDNS {
    $feed = Join-Path $installDir 'config\feed.txt'
    $feedName = if (Test-Path -LiteralPath $feed) { Get-Content -LiteralPath $feed -TotalCount 1 } else { $null }
    foreach ($address in @('127.0.0.1','::1')) {
        $port = if ($address -eq '::1') { 53 } else { 5354 }
        foreach ($tcp in @($false,$true)) {
            $deny = & $probe -Server $address -Port $port -Name blocked.example -Tcp:$tcp
            $allow = & $probe -Server $address -Port $port -Name example.com -Tcp:$tcp
            if ($deny.Status -ne 'REFUSED' -or $allow.Status -ne 'NOERROR' -or $allow.Answers -lt 1) {
                throw "Direct DNS verification failed on $address`:$port (TCP=$tcp)."
            }
            if ($feedName) {
                $feedDeny = & $probe -Server $address -Port $port -Name $feedName -Tcp:$tcp
                if ($feedDeny.Status -ne 'REFUSED') { throw "Feed verification failed on $address`:$port." }
            }
        }
    }
}
function Enable-Routing {
    $rules = @(Guard-Rules)
    if ($rules.Count -gt 1) { throw 'Multiple DNS Guard NRPT rules found.' }
    if ($rules.Count -eq 1 -and @($rules[0].NameServers) -notcontains '::1') {
        throw 'Existing DNS Guard NRPT rule points to an unexpected server.'
    }
    if (-not $rules.Count) {
        & $enableRoute -Persist
        if (-not @(Guard-Rules).Count) { throw 'DNS routing was not enabled.' }
    }
}
function Disable-Routing {
    if (@(Guard-Rules).Count) { & $disableRoute }
}
function Enable-BrowserPolicies {
    if (-not $BrowserPolicies) { return }
    if (Test-Path -LiteralPath $marker) {
        foreach ($policy in $policies) {
            $existing = Get-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
            if ($existing -and $existing.($policy.Name) -ne $policy.Value) {
                throw "Owned browser policy changed: $($policy.Path)\$($policy.Name)."
            }
            if (-not $existing) {
                New-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -Value $policy.Value `
                    -PropertyType $policy.Type -Force -ErrorAction Stop | Out-Null
            }
        }
    } else {
        foreach ($policy in $policies) {
            foreach ($path in @($policy.Path,($policy.Path -replace '^HKLM:', 'HKCU:'))) {
                if (Test-Path -LiteralPath $path) {
                    $existing = Get-ItemProperty -LiteralPath $path -Name $policy.Name -ErrorAction SilentlyContinue
                    if ($existing) { throw "Existing browser policy $path\$($policy.Name); inspect it manually." }
                }
            }
        }
        if ((Read-Host 'Type BROWSERS to disable browser DoH through managed policies') -cne 'BROWSERS') {
            throw 'Browser policy change cancelled.'
        }
        [IO.File]::WriteAllText($marker, 'DNS Guard owns Chrome/Edge/Firefox DNS policy values')
        try {
            foreach ($policy in $policies) {
                New-Item -Path $policy.Path -Force -ErrorAction Stop | Out-Null
                New-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -Value $policy.Value `
                    -PropertyType $policy.Type -Force -ErrorAction Stop | Out-Null
            }
        } catch {
            Disable-BrowserPolicies
            throw
        }
    }
    foreach ($policy in $policies) {
        $actual = Get-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -ErrorAction Stop
        if (-not ($actual.PSObject.Properties.Name -contains $policy.Name) -or
            $actual.($policy.Name) -ne $policy.Value) {
            throw "Browser policy verification failed: $($policy.Path)\$($policy.Name)."
        }
    }
}
function Disable-BrowserPolicies {
    if (-not (Test-Path -LiteralPath $marker)) { return }
    foreach ($policy in $policies) {
        $existing = Get-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
        if ($existing -and $existing.($policy.Name) -eq $policy.Value) {
            Remove-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -ErrorAction Stop
        }
    }
    Remove-Item -LiteralPath $marker -Force
}
function Ensure-FeedTask {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { return }
    if (-not (Test-Path -LiteralPath $updater -PathType Leaf)) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'scripts\Update-DNSBlocklist.ps1') -Destination $updater
    }
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $updater + '" -Destination "' + $feed + '"')
    $trigger = New-ScheduledTaskTrigger -Daily -At 03:00
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
        -User 'SYSTEM' -ErrorAction Stop | Out-Null
}
function Update-InstalledFeed {
    if (-not (Test-Path -LiteralPath $feed -PathType Leaf)) { throw 'Installed feed is missing.' }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') { throw 'Feed update task is running; retry later.' }
    $candidate = Join-Path $PSScriptRoot 'scripts\Update-DNSBlocklist.ps1'
    $backup = "$updater.previous-$([guid]::NewGuid().ToString('N'))"
    $hadUpdater = Test-Path -LiteralPath $updater -PathType Leaf
    if ($hadUpdater) { Copy-Item -LiteralPath $updater -Destination $backup }
    try {
        Copy-Item -LiteralPath $candidate -Destination $updater -Force
        & $updater -Destination $feed
        Write-Host "Feed updated. Previous updater: $backup. Previous feed: $feed.previous"
    } catch {
        $failure = $_.Exception.Message
        if ($hadUpdater) { Copy-Item -LiteralPath $backup -Destination $updater -Force }
        else { Remove-Item -LiteralPath $updater -Force -ErrorAction SilentlyContinue }
        throw "Feed update failed: $failure. Existing feed retained."
    }
}
function Show-Status {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    Write-Host "$serviceName service: $(if ($service) { $service.Status } else { 'not visible or not installed' })"
    try {
        $rules = @(Guard-Rules)
        Write-Host "DNS Guard routing rules: $($rules.Count)"
        if ($rules.Count -eq 1) {
            $allowed = @(Resolve-DnsName example.com -Type A -ErrorAction Stop | Where-Object { $_.IPAddress })
            $errors = @()
            $blocked = @(Resolve-DnsName blocked.example -Type A -ErrorAction SilentlyContinue `
                -ErrorVariable +errors | Where-Object { $_.IPAddress })
            $verified = $allowed.Count -gt 0 -and -not $blocked.Count -and $errors.Count -gt 0 -and `
                $errors[0].FullyQualifiedErrorId -like 'RCODE_REFUSED,*'
            Write-Host "Windows DNS block/allow: $(if ($verified) { 'passed' } else { 'failed' })"
        }
    } catch { Write-Host "Windows DNS routing check: $($_.Exception.Message)" }
    if (Test-Administrator) {
        try { Write-Host "Daily feed task: $(if (Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -EQ $taskName) { 'installed' } else { 'absent' })" }
        catch { Write-Host 'Daily feed task: unavailable to this session' }
    } else { Write-Host 'Daily feed task: requires Administrator to verify' }
    foreach ($policy in $policies) {
        $value = (Get-ItemProperty -LiteralPath $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue).($policy.Name)
        Write-Host "$($policy.Path)\$($policy.Name): $(if ($null -eq $value) { 'unset' } else { $value })"
    }
    if ($service -and $service.Status -eq 'Running') {
        try { Assert-DirectDNS; Write-Host 'Direct IPv4/IPv6 UDP/TCP block/allow: passed' }
        catch { Write-Host "Direct DNS check: $($_.Exception.Message)" }
    }
    Write-Host 'Browser coverage requires chrome://policy, edge://policy, about:policies and real browser DNS tests.'
}

if ($Action -eq 'status') { Show-Status; return }
Require-Administrator
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

switch ($Action) {
    'install' {
        if ($service) { throw 'Service already installed; use repair.' }
        if (-not $Config) { throw 'Install requires -Config pointing to a reviewed loopback configuration.' }
        if (@(Get-DnsClientNrptRule -ErrorAction Stop).Count) {
            throw 'Existing NRPT rules found; inspect them before installation.'
        }
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            throw 'Existing DNS Guard update task found; inspect it before installation.'
        }
        $sourceConfig = (Resolve-Path -LiteralPath $Config).Path
        $settings = Get-Content -LiteralPath $sourceConfig -Raw
        if ($settings -notmatch '(?m)^\s*listen_ipv4\s*=\s*127\.0\.0\.1\s*$' -or
            $settings -notmatch '(?m)^\s*listen_port\s*=\s*5354\s*$' -or
            $settings -notmatch '(?m)^\s*blocklist\s*=\s*blocked\.txt\s*$' -or
            $settings -notmatch '(?m)^\s*allowlist\s*=\s*allowed\.txt\s*$' -or
            $settings -notmatch '(?m)^\s*feedlist\s*=\s*feed\.txt\s*$') {
            throw 'Use a reviewed 127.0.0.1:5354 config with the standard list filenames.'
        }
        if ($settings -match '(?m)^\s*listen_ipv6_port\s*=' -and
            $settings -notmatch '(?m)^\s*listen_ipv6_port\s*=\s*53\s*$') {
            throw 'IPv6 loopback listener must use port 53.'
        }
        $sourceBinary = Join-Path $PSScriptRoot 'build\Release\dns_guard.exe'
        if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) { throw 'Build the Release executable first.' }
        if (Test-Path -LiteralPath $installDir) { throw 'Installation directory exists; inspect it before installing.' }
        New-Item -ItemType Directory -Path (Join-Path $installDir 'config') -Force | Out-Null
        try {
            Copy-Item -LiteralPath $sourceBinary -Destination $binary
            foreach ($file in @('blocked.txt','allowed.txt','feed.txt')) {
                $origin = Join-Path (Split-Path $sourceConfig) $file
                if (-not (Test-Path -LiteralPath $origin -PathType Leaf)) { throw "Missing list: $origin" }
                Copy-Item -LiteralPath $origin -Destination (Join-Path $installDir "config\$file")
            }
            if ($settings -notmatch '(?m)^\s*listen_ipv6_port\s*=') { $settings += "`nlisten_ipv6_port=53`n" }
            [IO.File]::WriteAllText($installedConfig, $settings)
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'scripts\Update-DNSBlocklist.ps1') -Destination $updater
            & $updater -Destination $feed
            & (Join-Path $PSScriptRoot 'scripts\Install-DNSGuard.ps1') -Executable $binary -Config $installedConfig
            Set-Service $serviceName -StartupType Automatic
            & sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed.' }
            Start-Service $serviceName
            (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
            Assert-DirectDNS
            Enable-Routing
            Enable-BrowserPolicies
            Ensure-FeedTask
            Write-Host 'Installed service and verified direct DNS. Check browser policies before claiming browser coverage.'
        } catch {
            $failure = $_.Exception.Message
            try {
                Disable-BrowserPolicies
                Disable-Routing
                if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }
                if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
                    & (Join-Path $PSScriptRoot 'scripts\Remove-DNSGuard.ps1')
                }
            } catch { throw "Install failed: $failure. Rollback failed: $($_.Exception.Message)." }
            throw "Install failed: $failure. Service and routing rolled back; files retained at $installDir."
        }
    }
    'start' {
        if (-not $service) { throw 'Service not installed.' }
        if ($service.Status -ne 'Running') { Start-Service $serviceName; $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30)) }
        Assert-DirectDNS
        Enable-Routing
        Enable-BrowserPolicies
    }
    'stop' {
        Disable-Routing
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service $serviceName
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
        }
        Write-Host 'Routing removed before service stop; browser policies remain until uninstall.'
    }
    'repair' {
        if (-not $service) { throw 'Service not installed.' }
        if ($service.Status -ne 'Running') { Start-Service $serviceName; $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30)) }
        Assert-DirectDNS
        Enable-Routing
        if ($UpdateFeeds) { Update-InstalledFeed }
        Enable-BrowserPolicies
        Ensure-FeedTask
        Write-Host 'DNS Guard service and routing checked.'
    }
    'uninstall' {
        $removalBackup = Join-Path $env:LOCALAPPDATA ('RogerfabDNSGuard-removed-' + [guid]::NewGuid().ToString('N'))
        Disable-Routing
        Disable-BrowserPolicies
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        if ($service) { & (Join-Path $PSScriptRoot 'scripts\Remove-DNSGuard.ps1') }
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            throw 'Windows has not released the service registration; files were kept in place.'
        }
        if (Test-Path -LiteralPath $installDir) {
            Move-Item -LiteralPath $installDir -Destination $removalBackup -ErrorAction Stop
        }
        Write-Host "Service, Guard routing, browser policies, task, and install files removed. Recovery copy: $removalBackup"
    }
}
