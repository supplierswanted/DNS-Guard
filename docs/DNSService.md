# DNS service operation

The service accepts DNS over UDP and TCP on configured loopback listeners, checks the queried name against the allowlist, blocklist, and optional feed, then either returns `REFUSED` or forwards the request to the configured upstream resolver. It is not an open resolver: configuration accepts loopback listener addresses only.

## Local test

The sample configuration listens on `127.0.0.1:5354` and uses `1.1.1.1` as an example upstream. Replace the numeric upstream address if needed.

```powershell
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
.\build\Release\dns_guard.exe .\config\loopback.conf
```

In another PowerShell window:

```powershell
.\scripts\Test-DNSGuard.ps1 -Name example.com
.\scripts\Test-DNSGuard.ps1 -Name blocked.example
.\scripts\Test-DNSGuard.ps1 -Tcp -Name example.com
```

The first query should be forwarded if the upstream is reachable. The second is blocked only if the name is in an active blocklist and not allowlisted. The test script reports the actual DNS response code.

## Lists and feed

`config/blocked.txt` and `config/allowed.txt` are local lists. `config/feed.txt` is a separate downloaded list. Use one ASCII domain per line; use punycode for internationalized names. Allowlist entries take precedence.

The updater's default sources are [HaGeZi Fake](https://github.com/hagezi/dns-blocklists), [URLhaus](https://urlhaus.abuse.ch/), and the [Malware Filter phishing list](https://gitlab.com/malware-filter/phishing-filter). Review each source's usage terms before redistributing its data. The updater requires HTTPS, validates the downloaded domain data, bounds its size and entry count, removes duplicates, and replaces the feed atomically. On failure it retains the last valid feed. The installed service can refresh through the scheduled task managed by `dns-guard.ps1`.

## Windows service management

Run these commands in elevated PowerShell:

```powershell
.\dns-guard.ps1 install -Config .\config\loopback.conf
.\dns-guard.ps1 status
.\dns-guard.ps1 start
.\dns-guard.ps1 stop
.\dns-guard.ps1 repair -UpdateFeeds
.\dns-guard.ps1 uninstall
```

Installation requires the reviewed sample listener settings and asks before enabling Guard-owned Windows DNS routing. The service runs as LocalService and has automatic restart recovery configured. `stop` removes the Guard-owned routing first. `uninstall` restores ordinary DNS routing, removes Guard-owned browser policies and the update task, then moves installed files to a recovery directory. Adapter DNS settings and the configured upstream are not changed.

The `status` action reports the service, routing, and update-task state. Feed updates can also be requested with `repair -UpdateFeeds`.

## Browser DNS limits

Optional managed policies can disable Chrome, Edge, and Firefox DoH. Install or repair with `-BrowserPolicies` and confirm the prompt. Verify the resulting policy at `chrome://policy`, `edge://policy`, and `about:policies`, then test a fresh browser session.

These policies do not control every application-specific encrypted DNS resolver, VPN resolver, direct-IP connection, or an already cached browser connection. Do not claim browser protection without verifying that browser's live DNS route.

