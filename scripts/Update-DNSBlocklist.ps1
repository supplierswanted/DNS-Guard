param(
    [Parameter(Mandatory)][string]$Destination,
    [string[]]$SourceUrl,
    [string]$SourceFile,
    [ValidateRange(1,32768)][int]$MinEntries = 100,
    [switch]$Rollback
)
$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $Destination).Path
if ((Get-Item -LiteralPath $target).PSIsContainer) { throw 'Destination must be an existing file.' }
$previous = "$target.previous"

if ($Rollback) {
    if (-not [IO.File]::Exists($previous)) { throw 'No previous blocklist is available.' }
    $swap = "$target.swap-$([guid]::NewGuid().ToString('N'))"
    [IO.File]::Replace($previous, $target, $swap, $true)
    [IO.File]::Move($swap, $previous)
    Write-Host 'Previous blocklist restored.'
    return
}
if ($SourceFile -and $SourceUrl) { throw 'Choose SourceFile or SourceUrl.' }
if (-not $SourceFile -and -not $SourceUrl) {
    $SourceUrl = @(
        'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt',
        'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt',
        'https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt'
    )
}
if ($SourceUrl.Count -gt 4) { throw 'At most four HTTPS sources are supported.' }

$utf8 = [Text.UTF8Encoding]::new($false, $true)
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$client = $null
try {
    if (-not $SourceFile) {
        Add-Type -AssemblyName System.Net.Http
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(20)
    }
    $inputs = if ($SourceFile) { @($SourceFile) } else { $SourceUrl }
    foreach ($input in $inputs) {
        if ($SourceFile) {
            $source = (Resolve-Path -LiteralPath $input).Path
            if ((Get-Item -LiteralPath $source).Length -gt 4MB) { throw 'Source file exceeds 4 MiB.' }
            $text = [IO.File]::ReadAllText($source, $utf8)
        } else {
            $uri = $null
            if (-not [Uri]::TryCreate($input, [UriKind]::Absolute, [ref]$uri) -or
                $uri.Scheme -ne 'https') { throw 'HTTPS source URL required.' }
            $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            try {
                if (-not $response.IsSuccessStatusCode) { throw "HTTPS source returned $([int]$response.StatusCode)." }
                if ($response.Content.Headers.ContentLength -gt 4MB) { throw 'HTTPS source exceeds 4 MiB.' }
                $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $memory = [IO.MemoryStream]::new()
                $buffer = [byte[]]::new(8192)
                try {
                    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        if ($memory.Length + $count -gt 4MB) { throw 'HTTPS source exceeds 4 MiB.' }
                        $memory.Write($buffer, 0, $count)
                    }
                    $text = $utf8.GetString($memory.ToArray())
                } finally {
                    $memory.Dispose()
                    $stream.Dispose()
                }
            } finally { $response.Dispose() }
        }
        foreach ($raw in ($text -split '\r?\n')) {
            $domain = $raw.Trim().Trim([char]0xFEFF)
            if (-not $domain -or $domain.StartsWith('#') -or $domain.StartsWith('!')) { continue }
            if ($domain.EndsWith('.')) { $domain = $domain.Substring(0, $domain.Length - 1) }
            $domain = $domain.ToLowerInvariant()
            $address = $null
            if ([Net.IPAddress]::TryParse($domain, [ref]$address)) { continue }
            if ($domain.Length -gt 253 -or $domain -notmatch '^[a-z0-9_-]+(\.[a-z0-9_-]+)+$') {
                throw "Invalid domain in source: $domain"
            }
            foreach ($label in ($domain -split '\.')) {
                if ($label.Length -gt 63) { throw "Invalid domain label in source: $domain" }
            }
            [void]$seen.Add($domain)
            if ($seen.Count -gt 32768) { throw 'Blocklist exceeds 32768 domains.' }
        }
    }
    if ($seen.Count -lt $MinEntries) { throw "Source has fewer than $MinEntries domains." }
    [string[]]$sorted = @($seen)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $stage = "$target.next-$([guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllLines($stage, $sorted, [Text.UTF8Encoding]::new($false))
        [IO.File]::Replace($stage, $target, $previous, $true)
    } finally {
        if ([IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
    }
    Write-Host "Updated blocklist: $($seen.Count) domains. Previous version: $previous"
} finally {
    if ($client) { $client.Dispose() }
}
