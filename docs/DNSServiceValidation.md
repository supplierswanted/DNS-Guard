# Local DNS service verification — 2026-11-19

Historical snapshot. Windows Application Control was changed later by the user;
for current Windows/Docker results and remaining routing limits, see
[WindowsMonitoring.md](WindowsMonitoring.md).

## Implemented phases

1. Loopback UDP receive, bounded parsing, isolated connected upstream socket,
   OS-random ID, exact ID/opcode/question checks and restored client ID.
2. TCP framing and reuse, 16-message connection limit, fixed worker count, bounded
   queue and one deadline covering queue wait and all client/upstream operations.
   Stop cancels queued jobs and joins active workers. UDP TC retries TCP.
3. Existing domain-list evaluation, allow precedence, parent-domain matching and
   valid REFUSED response without contacting upstream for blocked names.
4. Strict key=value configuration and bounded ASCII domain-list loading.
5. Console and actual Windows SCM host, manual-start LocalService install/remove
   scripts and explicit-confirmation adapter backup/switch/restore instructions.
   Windows service installation and system DNS changes were not executed.
6. Browser-specific official sources and verification method documented.
   Browser/DoH coverage was not tested or claimed.

## Final verification

| Environment | Actual result |
|---|---|
| Windows MinGW GCC Release | Configure/build succeeded |
| Windows MSVC Release | Configure/build succeeded |
| Windows runtime | Application Control blocked dns_guard startup with WinError 4551. Network test ran zero cases; native service lifecycle remains unverified. |
| Linux GCC 12 Release | All 14 CTest groups passed |
| Linux Clang 14 Release + ASan/UBSan, non-PIE | All 14 CTest groups passed |
| Network group | 15 real socket cases passed: local fake UDP/TCP peer, forwarding, split TCP/reuse, same client IDs, block/allow, malformed input, mismatches, timeout, unreachable peer, TC fallback, UDP size limit, overload/recovery, invalid configs, shutdown and transfer refusal |
| Live upstream smoke | example.com via the configured container resolver 192.168.65.7 returned 83-byte replies with two A records over both UDP and TCP |
| Parser fuzz | 100,000 instrumented inputs, seed 19, no crash reported (parser fuzzing does not cover socket state machines) |
| Scripts | Install/remove and documented PowerShell blocks parsed; no service or adapter state was changed |

Commands used in the Linux validation container:

```sh
cmake -S /src -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/build
ctest --test-dir /tmp/build -R proxy_network --output-on-failure
ctest --test-dir /tmp/build --output-on-failure
cmake -S /src -B /tmp/asan -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release -DDNS_SANITIZE=ON -DDNS_FUZZ=ON -DCMAKE_EXE_LINKER_FLAGS=-no-pie
cmake --build /tmp/asan
ctest --test-dir /tmp/asan --output-on-failure
/tmp/asan/dns_fuzz -runs=100000 -seed=19
```

No open resolver was created, no privileged port was bound on the Windows host,
and adapter DNS was not changed. Default bind is 127.0.0.1:5353. The sample
blocklist is demonstration configuration, not a maintained malicious-domain feed.
The service has no DNSSEC validation, DoH interception, IPv6 transport listener,
authenticated DNS forwarding or zone-transfer support. Full target-host operation,
SCM stop/restart, runtime packaging and browser routing must be verified before
Windows production use. Existing parser throughput measurements do not measure
this bounded forwarding service's network throughput.
