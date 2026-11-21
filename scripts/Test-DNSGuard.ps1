[CmdletBinding()]
param(
    [string]$Name = 'example.com',
    [ValidateSet('127.0.0.1','::1')][string]$Server = '127.0.0.1',
    [ValidateRange(1,65535)][int]$Port = 5354,
    [switch]$Tcp
)
$ErrorActionPreference = 'Stop'
$packet = [Collections.Generic.List[byte]]::new()
$id = [byte[]]::new(2)
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($id) } finally { $random.Dispose() }
$packet.AddRange($id)
$packet.AddRange([byte[]](1,0,0,1,0,0,0,0,0,0))
$wireName = [Collections.Generic.List[byte]]::new()
foreach ($label in $Name.TrimEnd('.').Split('.')) {
    if ($label.Length -lt 1 -or $label.Length -gt 63 -or $label -notmatch '^[a-zA-Z0-9_-]+$') {
        throw 'Use a valid ASCII DNS name.'
    }
    $wireName.Add([byte]$label.Length)
    $wireName.AddRange([Text.Encoding]::ASCII.GetBytes($label))
}
$wireName.Add(0)
if ($wireName.Count -gt 255) { throw 'DNS name is too long.' }
$packet.AddRange($wireName)
$packet.AddRange([byte[]](0,1,0,1))
$family = if ($Server -eq '::1') { [Net.Sockets.AddressFamily]::InterNetworkV6 } else { [Net.Sockets.AddressFamily]::InterNetwork }

function Read-Exactly($Stream, [int]$Count) {
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $n = $Stream.Read($buffer,$offset,$Count-$offset)
        if ($n -eq 0) { throw 'TCP connection closed before response completed.' }
        $offset += $n
    }
    return ,$buffer
}

if ($Tcp) {
    $client = [Net.Sockets.TcpClient]::new($family)
    try {
        $client.ReceiveTimeout = 3000
        $client.SendTimeout = 3000
        if (-not $client.ConnectAsync($Server,$Port).Wait(3000)) { throw 'TCP connect timeout.' }
        $stream = $client.GetStream()
        $prefix = [byte[]]([byte]($packet.Count -shr 8),[byte]($packet.Count -band 255))
        $stream.Write($prefix,0,2)
        $bytes = $packet.ToArray()
        $stream.Write($bytes,0,$bytes.Length)
        $prefix = Read-Exactly $stream 2
        $response = Read-Exactly $stream (($prefix[0] -shl 8) -bor $prefix[1])
    } finally { $client.Dispose() }
} else {
    $client = [Net.Sockets.UdpClient]::new($family)
    try {
        $client.Client.ReceiveTimeout = 3000
        $client.Connect($Server,$Port)
        $bytes = $packet.ToArray()
        [void]$client.Send($bytes,$bytes.Length)
        $any = if ($Server -eq '::1') { [Net.IPAddress]::IPv6Any } else { [Net.IPAddress]::Any }
        $peer = [Net.IPEndPoint]::new($any,0)
        $response = $client.Receive([ref]$peer)
    } finally { $client.Dispose() }
}
if ($response.Length -lt 12 -or $response[0] -ne $id[0] -or $response[1] -ne $id[1] -or
    ($response[2] -band 128) -eq 0) { throw 'Invalid DNS response header or ID.' }
$rcode = $response[3] -band 15
$status = switch ($rcode) { 0 { 'NOERROR' } 2 { 'SERVFAIL' } 3 { 'NXDOMAIN' } 5 { 'REFUSED' } default { "$rcode" } }
[pscustomobject]@{
    Name = $Name
    Server = $Server
    Transport = $(if ($Tcp) { 'TCP' } else { 'UDP' })
    Port = $Port
    Status = $status
    Answers = ($response[6] -shl 8) -bor $response[7]
    Bytes = $response.Length
}
