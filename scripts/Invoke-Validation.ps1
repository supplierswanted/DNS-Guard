[CmdletBinding()]
param(
    [string]$BuildDirectory = "build",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host "==> $Name $($Arguments -join ' ')"
    & $Name @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Name' failed with exit code $LASTEXITCODE."
    }
}

try {
    $cmake = Get-Command cmake -ErrorAction Stop
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $buildPath = Join-Path $projectRoot $BuildDirectory

    Invoke-CheckedCommand -Name $cmake.Source -Arguments @(
        "-S", $projectRoot,
        "-B", $buildPath,
        "-DBUILD_TESTING=ON",
        "-DCMAKE_BUILD_TYPE=$Configuration"
    )
    Invoke-CheckedCommand -Name $cmake.Source -Arguments @(
        "--build", $buildPath,
        "--config", $Configuration,
        "--parallel"
    )

    $ctest = Get-Command ctest -ErrorAction Stop
    Invoke-CheckedCommand -Name $ctest.Source -Arguments @(
        "--test-dir", $buildPath,
        "-C", $Configuration,
        "--no-tests=error",
        "--output-on-failure"
    )

    Write-Host "Validation passed."
    exit 0
}
catch {
    Write-Host "Validation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
