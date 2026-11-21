# DNS Guard

 DNS Guard is a Windows DNS forwarding and monitoring service. It checks queried domains against local allow/block lists and an optional threat feed. Blocked names receive `REFUSED`; allowed queries are forwarded to the configured upstream resolver.

The service is intended as an additional local DNS filtering layer. It does not inspect arbitrary application traffic, decrypt DoH/DoT/DoQ, block direct-IP connections, or guarantee detection of every malicious domain.

## Build and test

Requires CMake 3.20+, a C++20 compiler, and Python 3 for the socket integration tests.

```powershell
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

The Docker test image builds the project and runs CTest:

```powershell
docker build -f Dockerfile.test -t rogerfab-dns-guard:test .
docker run --rm rogerfab-dns-guard:test
```

## Run locally

Review `config/loopback.conf` and set `upstream_ipv4` to the numeric IPv4 address of the resolver you intend to use. The example uses `1.1.1.1`. The sample listener is `127.0.0.1:5354`.

```powershell
.\build\Release\dns_guard.exe .\config\loopback.conf
.\scripts\Test-DNSGuard.ps1 -Name example.com
.\scripts\Test-DNSGuard.ps1 -Name blocked.example
```

`config/blocked.txt` and `config/allowed.txt` accept one ASCII domain per line; use punycode for internationalized names. An allowlist match takes precedence over a blocklist match.

## Windows service

From an elevated PowerShell window, install using a reviewed loopback configuration:

```powershell
.\dns-guard.ps1 install -Config .\config\loopback.conf
.\dns-guard.ps1 status
```

The script installs an automatic LocalService Windows service, checks DNS behavior, configures the Guard-owned Windows DNS routing, and schedules feed updates. Browser DoH policies are optional and require `-BrowserPolicies` plus explicit confirmation. Review managed browser policies and test the browser's actual DNS path separately.

```powershell
.\dns-guard.ps1 start
.\dns-guard.ps1 stop
.\dns-guard.ps1 repair -UpdateFeeds
.\dns-guard.ps1 uninstall
```

`stop` removes the Guard-owned DNS routing before stopping the service. `uninstall` removes only Guard-owned routing and managed policy values; it moves the installation directory to a recovery folder instead of deleting its configuration and lists. Adapter DNS settings are not changed.

See [DNS service operation](docs/DNSService.md), [Windows monitoring limits](docs/WindowsMonitoring.md), and [performance results](docs/Performance.md).

