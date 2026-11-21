# Code architecture

## Request flow

```text
UDP/TCP listener
  -> bounded DNS parser
  -> allowlist/blocklist/feed evaluation
  -> REFUSED response or bounded upstream forwarding
  -> validated response returned to the client
```

The resolver and service entry point live in `app/` and `src/DNSProxy.cpp`. DNS message parsing is split across the public interfaces in `include/dnsguard/` and their implementations in `src/`. Domain-list evaluation, rate monitoring, and traffic collection are separate library components. Windows DNS event observation is an optional read-only program in `app/DNSMonitorMain.cpp`.

## Project layout

- `app/` — resolver and Windows event-monitor entry points.
- `include/dnsguard/` — public C++ interfaces.
- `src/` — parser, proxy, configuration, list, cache, and monitoring implementations.
- `tests/` — unit, integration, script, and fixture tests.
- `fuzz/` — parser fuzz target.
- `bench/` — benchmark sources, instructions, and retained measurement results.
- `config/` — sample loopback configuration and domain lists.
- `scripts/` — Windows service, feed, and diagnostic scripts.
- `docs/` — operational, monitoring, and performance notes.

Build targets and optional test/benchmark switches are defined in the root `CMakeLists.txt`.
