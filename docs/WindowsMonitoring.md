# Windows DNS observation and active protection

`dns_monitor.exe CONFIG` is an **optional, read-only console monitor**. It loads
the same allow/block lists as `dns_guard.exe` and subscribes to future DNS Client
Operational completion events (3008) with the Windows Event Log API. It does not listen on
port 53, change the resolver, or modify the running Guard service. It prints the
domain, record type, event status and provider PID when those fields are present,
and the list decision. The PID in a provider event may be the DNS Client service,
**not the application that requested the lookup**. Time is sampled when the event
is processed, not asserted to be the DNS query's original timestamp. A single
push callback and one consumer use a 256-event queue with bounded field sizes;
the Windows event channel
has its own finite size and may lose records under load. Counts are for observed
events, not unique sites or blocked connections. A repeated completion event is
still counted; no cross-event deduplication guarantee is claimed.

The computer's Operational channel was initially disabled. An administrator
enabled it manually on 2026-11-20. Smart App Control initially blocked newly
built executables; the user then disabled it. A live Windows test subsequently
observed `blocked.example` (`type=1`, `status=9003`, `list=DENY`) and
`example.com` (`type=1`, `status=0`, `list=allow`). This confirms event receipt
and list matching, not blocking or complete DNS coverage. No Windows DNS server
setting was changed. The monitor never changes the channel setting itself.

The deployed Guard listens on `127.0.0.1:5354` and `[::1]:53` UDP/TCP with upstream
`1.1.1.1:53`. The active Wi-Fi adapter currently uses `192.168.1.1`. Events from
applications that bypass Windows DNS Client (such as browser DoH, DoT, direct IP,
or their own resolver) are outside this channel's coverage. List matches from
this monitor **do not block a query**. There is no threat-intelligence feed in the
project; the configured blocklist is its only source of deny decisions.

## Active protection: scoped Windows routing tested

The proxy now has an optional `listen_ipv6_port`. When set to `53`, it also
binds **only** `[::1]:53` for UDP/TCP, while retaining its configured IPv4
listener (currently `127.0.0.1:5354`) and unchanged upstream. A live isolated
Windows test returned DNS `REFUSED` for `blocked.example` and `NOERROR` for
`example.com` over both UDP and TCP on `[::1]:53`, with the original Windows
Guard service still running. The integrated proxy also rejects an upstream
CNAME whose target is denied, including an allowlist override test. This is
real DNS-level blocking **for clients that actually use that listener**.

Windows still uses its adapter DNS (`192.168.1.1` and `fe80::1`) unless a DNS
policy routes selected names to `[::1]:53`. `SharedAccess` (ICS) owns IPv4
`0.0.0.0:53`, but did not conflict with the IPv6-only listener in the live
test. A temporary NRPT rule was added and removed in the scoped trial below;
no adapter or firewall setting was changed. The Program Files service was
subsequently upgraded to this IPv6-capable binary as documented below.

A scoped trial on 2026-11-20 added one temporary Windows NRPT rule for
`example.com` pointing to `::1`, while the candidate answered direct blocked
queries with `REFUSED` and direct allowed queries with `NOERROR`. Windows
resolved `example.com` before the rule, did not resolve it while the rule was
active, and resolved it again after removal. The script removed only its own
rule, then stopped its candidate. A separate read-only check found zero trial
rules, no candidate process, and two A records from ordinary Windows resolution.
This is evidence for the scoped Windows DNS path, but no packet capture proved
the exact packets and no browser path was tested. The adapter's DNS servers
remained intact. The broader root namespace was validated later as described below.

The administrator trial script is
`scripts/Invoke-ScopedDNSProtectionTrial.ps1`. It builds a temporary config
using the current upstream address, starts a separate candidate on `[::1]:53`,
checks direct `REFUSED` for `example.com`, direct allowed resolution for
`example.org`, and ordinary Windows resolution before asking for explicit
`YES`. It then adds only an `example.com` NRPT rule, checks Windows resolution,
removes that exact rule in `finally`, and stops only its candidate
process. It does not alter adapter DNS servers, firewall rules, ICS or the
installed Guard service. If the PowerShell process is forcibly killed after
the rule is added, inspect `Get-DnsClientNrptRule` and remove **only the printed
trial rule name** with `Remove-DnsClientNrptRule -Name <name> -Force` before
stopping the candidate. The trial was explicitly approved and run by the user.

For continuous deployment on this host, the installed service runs as
`LocalService` from `C:\Program Files\RogerfabDNSGuard\dns_guard.exe`, using
`config\loopback.conf` in that directory. On 2026-11-20 the user approved and
ran the service upgrade. The script backed up the old binary/config in
`rollback-c1fe80520a8341ddad660a8c2e7ccefd`, installed the tested binary,
and added only `listen_ipv6_port=53`. An independent read-only check confirmed
the installed and source SHA-256 hashes match, upstream remains `1.1.1.1:53`,
IPv4 remains `127.0.0.1:5354`, and the service is running. The same service PID
owned IPv4 UDP/TCP 5354 and IPv6 UDP/TCP 53. Direct block/allow checks passed
on all four paths: `blocked.example` was `REFUSED`, `example.com` was `NOERROR`
with two A answers. ICS still owned IPv4 `0.0.0.0:53`. There were zero NRPT
rules immediately after the upgrade; routing was enabled in a later step.

`scripts/Update-DNSGuardService.ps1` implements this exact host-specific
upgrade. `-Preview` performs read-only preflight checks. The actual run stores
the previous executable and config under a printed `rollback-*` directory in
the protected deployment folder, compares the installed executable's SHA-256
to the tested source, and probes block/allow over IPv4/IPv6 UDP/TCP. On failure
it restores both files and restarts the prior service. If even automatic
rollback fails, use the printed directory to restore those two files after
stopping **only** `RogerfabDNSGuard`; then start that service again. Neither
the preview nor this upgrade adds an NRPT rule. The `-Preview` and installed
service probes passed; the automatic rollback branch has not been exercised.

Microsoft documents `.` as the NRPT `Any` namespace. A temporary all-domain
rule pointing to `::1` could now be tested, with
the exact rule identity recorded and immediate rollback on failure. It would
affect ordinary Windows DNS client queries; it is broader than the completed
`example.com` trial and requires its own approval. DoH, custom application DNS
and direct IP connections remain outside this guarantee.
[NRPT namespace reference](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule)

`scripts/Invoke-AllDomainDNSProtectionTrial.ps1 -Preview` checks the current
service, empty NRPT table, direct block/allow answers and ordinary Windows DNS
without changing policy. Its actual administrator run asks for `YES`, adds a
unique `.` rule, checks the effective policy, allowed names and a blocked
lookup, then removes only its own rule in `finally` and verifies normal DNS
again. On 2026-11-20 the user approved and ran the all-domain trial. The
effective policy check passed; Windows reported
`RCODE_REFUSED,Microsoft.DnsClient.Commands.ResolveDnsName` for
`blocked.example`, while `example.com` and `example.org` resolved. The script
removed its unique rule and reported restored ordinary DNS. An independent
read-only check found zero NRPT rules, two A records for `example.com`, the
Guard service still running on `[::1]:53`, and ICS still on IPv4 `0.0.0.0:53`.
This verifies ordinary Windows DNS Client behavior during the temporary rule;
that unique trial rule was removed. A distinct persistent rule was installed
later, as described below. If the PowerShell
window is forcibly closed after it prints the rule name, remove that exact
rule with `Remove-DnsClientNrptRule -Name <printed-name> -Force`, then run
`Clear-DnsClientCache`. Do not remove unrelated rules.

The same script now supports an explicit `-Persist` mode, which uses a distinct
`RogerfabDNSGuardPolicy-*` identity and requires typing `PERSIST`. It keeps the
rule only after effective-policy, allow, and exact `RCODE_REFUSED` checks pass;
errors still remove the new rule. `scripts/Disable-DNSGuardPolicy.ps1` removes
only that identified persistent rule and clears the Windows DNS cache. The
user approved and ran `-Persist`; the exact Windows DNS error for both A and
AAAA queries to `blocked.example` and `child.blocked.example` was
`RCODE_REFUSED`, while `example.com` and `example.org` each returned two A
records. The emergency disable script then removed that policy; independent
checks found zero NRPT rules and restored ordinary resolution. The user ran
`-Persist` again, and independent checks confirmed the new rule
`{A61F77B3-254D-40DE-A7DF-1C76F4E18C42}` remains active and effective.

Before persistence, the user configured SCM recovery with `sc.exe failure
RogerfabDNSGuard reset= 86400 actions= restart/5000/restart/5000/restart/5000`.
`sc.exe qfailure` showed three 5-second restart actions; the service remained
running. The previous service configuration had no failure actions;
`sc.exe failure RogerfabDNSGuard reset= 0 actions= ""` restores that setting
after the DNS Guard policy is disabled, if desired. **Actual crash recovery
was not tested.** If the service cannot start while the root NRPT rule is
active, ordinary Windows DNS may fail until the rule is removed. This is a
fail-closed pilot, not a verified high-availability protection service.
[Service recovery command reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742019%28v%3Dws.11%29)

Windows Filtering Platform can classify UDP/TCP 53 traffic, but a transport/IP
filter sees endpoints and packets, not a reliable domain-policy decision. Blocking
an IP may affect unrelated domains sharing it. Domain-level blocking needs a DNS
aware interception point or directing the Windows resolver through a local DNS
service, validating packets, preserving transaction identity, and answering before
the caller uses the result. A WFP callout would require signed driver deployment
and explicit rollback; no filter or driver is installed by this project. DoH/DoT
and browser Secure DNS need separate policy/visibility and must not be counted
as covered by UDP/TCP 53. Previously cached browser responses and direct-IP
connections also bypass new DNS decisions. Failure of the Guard listener after
adding NRPT will cause DNS failures for the redirected namespace; automatic
fail-open is not implemented. Rollback removes the rule to restore the original
resolver path.

For a future active phase: keep passive observation independent, make allowlist
override deny, log decisions with bounded retention, test false positives against
shared hosting and IDNs, and keep an emergency disable/rollback path. The
current DNS path returns SERVFAIL on upstream failure; a redirected namespace
does not automatically fall back to the original resolver. A different fail-open
policy needs separate design and approval.
Any adapter-DNS, firewall, WFP, or driver change requires a reviewed deployment
plan and explicit user approval.

Build from the repository root and run `build/Release/dns_monitor.exe
config/loopback.conf` in a console; Ctrl+C stops it. The Operational channel
was enabled manually by the user. The installed `RogerfabDNSGuard` service is
unaffected. If reverting monitoring, disable the channel only if it was
previously disabled and no other tool relies on it.

Verification on 2026-11-20: the isolated MSVC candidate passed 15/15 CTest
groups, including the opt-in live Windows monitor test; MinGW passed 14/14.
The final Docker build (`docker build -f Dockerfile.test -t dns-guard-test:local .`)
from the workspace root compiled with Linux GCC 12.2 and passed 14/14 CTest
groups. The clean root Windows MSVC build passed 15/15 groups (including the
opt-in live monitor test), and the root MinGW build passed 14/14. A single-round local
benchmark of the root MSVC build is at `../bench/results/proxy-current.json`:
2,000/2,000
successful ordinary UDP forwards, blocks, TCP forwards, and 4,096-list misses
each. UDP-forward p95 was 0.311 ms, TCP p95 25.592 ms, and the small UDP
forward peak process RSS was 6,496,256 bytes. The peer was local and simulated;
these are not internet latency or maximum capacity measurements. Bounded bursts
have expected timeout/overload failures. Long-running
event-loss behavior remain unverified.

The latest Windows integration suite also runs `Test-DNSGuard.ps1` against an
isolated IPv6 listener for blocked and allowed names over UDP and TCP. The
script now accepts `-Server ::1` in addition to its existing IPv4 default.
Browser bypass and Windows DNS cache have not been tested. The service upgrade
passed direct socket checks; persistent Windows DNS routing was tested later as
reported below. Generated CMake directories and build snapshots are excluded
from the published source tree. Historical measurements are retained in
`bench/results/`; rebuild the monitor locally using the command above.

Final verification with the persistent NRPT rule active: Windows MSVC CTest
15/15, MinGW CTest 14/14; the root Docker build completed and `docker run --rm
dns-guard-test:local` passed 14/14 Linux tests. The Docker layers were cached
because C++ and test sources had not changed; the container test run was fresh.
Windows DNS Client A and AAAA requests for `blocked.example` and its child
returned `RCODE_REFUSED`, while `example.com` and `example.org` resolved.

## Driver decision (2026-11-20 source audit)

No kernel driver is needed for the currently supported Windows DNS Client path:
the existing user-mode DNS service decides on the question before forwarding,
and the explicitly installed NRPT rule directs ordinary Windows DNS Client
queries to it. A user-mode WFP filter could block selected endpoints or ports,
but that would not itself make a reliable domain decision. A callout driver
would be justified only by a separately specified interception requirement
that built-in filtering and resolver routing cannot meet. It would add kernel
crash risk, WDK and signing requirements, deployment privilege, and a more
complex rollback path. No driver source, WFP filter, or installation step was
added in this audit. See [Microsoft's WFP guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations)
and [driver signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing).

The current NRPT route still does not cover application-controlled DNS, browser
DoH, DoT, direct-IP traffic, or already cached browser answers. The monitor
prints full query names and PIDs to stdout; operators must restrict access and
retention if they redirect this output to a log. The service itself does not
provide automatic fail-open or proven high availability; use the documented
NRPT removal script to restore the original resolver route after failure.
