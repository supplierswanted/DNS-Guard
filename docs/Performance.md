# Performance engineering results — 2026-11-19

Only two production files changed: DNSProxy.cpp and DNSDomainLists.cpp.
The public interfaces, timeout/worker/queue limits, parser budgets, response
validation and allow/block behavior are preserved.

## Baseline and method

The original source and executable were captured locally before changes.
Generated snapshots are excluded from this publishable source tree; the raw
per-scenario samples are retained under `../bench/results/`. Network results
record executable SHA-256 hashes and platform. Measurements used this
Intel Core 7 150U Windows machine, MSVC Release, three rounds of nine scenarios.
Each ordinary scenario sent 2,000 requests per round, 6,000 total, to a separate
loopback fake upstream. The ordinary query and fake reply are only 29 bytes
(no answer records); they do not model internet resolver delay. TCP reconnects
every eight requests. Python client/fake-peer/scheduler overhead is included.
The measured rates are workload throughput, not maximum service capacity.

The initial fixture selected UDP ports before TCP, which collided with Windows
TCP TIME_WAIT after repeated short connections. Two complete baseline rounds
were retained and the third repeated after fixing setup to select TCP first.
Request/response operations and timing were unchanged. The fixture now closes
half-created sockets and retries a bounded number of times. No SO_REUSE setting
was used to bypass exclusive binds.

## Measured final changes

1. UDP receipt previously allocated and initialized a 65,536-byte vector for
   every packet, then shrank its size while retaining its capacity in the queue.
   The listener now receives into one fixed scratch array and queues an owned
   copy of only the received bytes. Upstream UDP receipt similarly uses a
   bounded stack array, then owns only the actual response bytes. Every byte
   copied is within the successful receive count. The original size checks remain.
2. Strict parent-domain matching rejects candidates whose wire length is at
   least the query name's length before validating/scanning that impossible
   candidate. Actual suffix comparisons and validation remain intact.

| Metric | Before | Final | Interpretation |
|---|---:|---:|---|
| Small UDP forwarding median completed/s | 2,541 | 4,221 | +66%; all 6,000 succeeded in both |
| Small UDP p50 | 0.269 ms | 0.171 ms | Lower in this controlled workload |
| Small UDP p95 | 0.698 ms | 0.328 ms | About 53% lower |
| Small UDP p99 | 0.961 ms | 0.510 ms | Lower in this controlled workload |
| 4,096-list miss, network p95 | 0.536 ms | 0.366 ms | Short queries against longer candidates |
| TCP network p95 | 25.592 ms | 26.373 ms | No improvement demonstrated |
| Queue64 small-query burst, peak working set | 10.066 MiB | 6.043 MiB | About 40% lower |
| Queue256 small-query burst, peak working set | 22.172 MiB | 6.078 MiB | About 72.6% lower |
| Queue256/500ms, peak private commit | 17.750 MiB | 1.363 MiB | About 92.3% lower |

Memory is sampled from the service process every 5ms. It excludes the fake peer
and client and can miss brief peaks. The memory win is under pressure from many
small queued packets; maximum-sized packet pressure was not profiled. Normal
forwarding working set after the scenario rose slightly, about 0.18 MiB, because
scratch/worker stack storage remains committed. This is not an across-the-board
idle RAM reduction. Windows stack reservation and socket kernel buffers are not
the cumulative heap bytes reported below.

Timeout losses were preserved, not optimized away. With 256 waiting slots,
two workers, a 20ms delayed peer and 500ms timeout, both versions returned 138
successful replies out of 798 attempts over three rounds. With 1500ms the
counts were 411 before and 410 final. Queue64/1500ms returned 198/222 in both.
Increasing timeout retains work longer and changes completion counts. No defaults
were lowered to obtain favorable latency percentiles. RTT percentiles include
only successful expected-code replies; failures are separate in the JSON.

## Allocation and component profiling

Linux GCC Release, three identical repetitions of 1,000 requests using an
isolated profiling host overriding ordinary new, excluding startup:

| Scenario | Cumulative requested heap bytes before | Final | Allocation calls before/final |
|---|---:|---:|---:|
| Forward UDP | 131,259,944 | 245,944 | 8,111 / 8,111 |
| Block UDP | 65,678,944 | 171,944 | 5,111 / 5,111 |

Requested heap traffic fell about 99.8%/99.7%; allocation call counts did not
fall. These are cumulative requested bytes, not RSS or simultaneously resident
memory. Per-request 64KiB heap allocations disappeared (2,000/1,000 before,
zero final) while the bounded receive storage moved to scratch/stack memory.
Linux allocation results are not substituted for Windows RSS measurements.

Native Windows MinGW component benchmark, five repetitions, median:

| Component | Before | Final |
|---|---:|---:|
| 4,096 equal-width list candidates, miss | 52.206 us | 19.924 us |
| 4,096 list candidates, last exact hit | 21.262 us | 20.848 us |
| Cache1024, last hit | 7.457 us | 7.212 us |
| Cache1024, miss | 6.882 us | 6.770 us |
| Rate4096, last hit | 27.166 us | 26.590 us |
| Rate4096, miss | 29.972 us | 28.977 us |
| Rate4096, four-thread hit | 28.611 us/op | 28.250 us/op |
| Collector ingest/pop | 87.6 ns/pair | 84.4 ns/pair |

Only list miss acceleration is attributed to changed component code; other
differences are repeat/scheduling noise. Cache/rate linear scans remain bounded.
They are not in the proxy forwarding path, and caching preserves owned-copy
semantics (two small allocations per cache hit). No extra index, allocator,
lock-free queue, cache format or hash state was added. The queue synchronization
cost was far below list/rate scan cost in these measurements. Four-producer
queue attempts include capacity rejections; raw logs retain accepted/drop counts.

A TCP_NODELAY experiment did not improve Windows TCP tails (candidate p95
27.630ms versus 25.592ms baseline), so it was removed. Its results remain
separate from final results. Blocked UDP p99 also varied upward from 0.267 to
0.318ms despite a lower median/p95; no universal tail-latency claim is made.

## Verification and artifacts

- MSVC Release and MinGW Release: builds and all 14 CTest groups passed on Windows.
- Linux GCC Release: all 14 groups passed.
- Linux Clang ASan/UBSan, non-PIE: all 14 groups passed.
- The network group now has 16 cases, including a 62KB UDP/EDNS request and
  response-size enforcement. Windows skips the POSIX signal-specific shutdown
  case; SCM/console stop lifecycle remains a separate deployment check.
- Allocation-failure, parser malformed-input, concurrency and bounds regressions
  remain in the existing suite. Sanitizers did not report an error in these runs.

See [benchmark instructions](../bench/README.md) and
[raw results](../bench/results/). Source-level profiling is opt-in with
DNS_BENCHMARKS=ON; production binaries contain no allocation counters.
Build outputs are intentionally excluded from the source tree. Rebuild the
optimized executable with the commands in [benchmark instructions](../bench/README.md).
The previously running user service was not stopped or replaced during these
measurements.

## 2026-11-20 correctness audit measurements

The current audit fixed CNAME policy correctness, not a measured performance
bottleneck. The three-round Windows MSVC Release loopback benchmark used 2,000
requests per ordinary scenario, a local fake upstream, and the same machine.
Windows process RSS was sampled every 5 ms; short peaks can be missed. The
benchmark's random port selection was changed after a Windows reserved-port
failure. That and concurrent system activity limit direct latency comparison.

| Scenario | Baseline p95 / requests per second | Final p95 / requests per second | Baseline/final peak RSS | Failed requests (3 rounds) |
|---|---:|---:|---:|---:|
| UDP forward | 0.489 ms / 3,428 | 0.892 ms / 2,137 | 6.22 / 6.21 MiB | 0 / 0 |
| UDP block | 0.185 ms / 7,111 | 0.337 ms / 5,051 | 5.80 / 5.79 MiB | 0 / 0 |
| TCP forward | 29.840 ms / 81 | 27.693 ms / 91 | 6.25 / 6.23 MiB | 0 / 0 |
| 4,096-list miss | 0.443 ms / 3,459 | 1.041 ms / 1,968 | 6.45 / 6.47 MiB | 0 / 0 |
| Queue256, 500 ms timeout | 479.630 ms / 37 | 481.025 ms / 37 | 6.11 / 6.12 MiB | 656 / 654 |

Queue overload failures are expected with two workers and a 20 ms delayed
peer. The remaining scenarios and raw per-round failures are in
`../bench/results/proxy-audit-baseline.json` and
`../bench/results/proxy-audit-final.json`. No speed or
RAM improvement is claimed. The isolated allocation probe produced identical
baseline/final counts: 8,002 allocations and 190,248 requested bytes per
1,000 forwards; 5,002 and 116,248 per 1,000 blocks. Component medians were
also broadly unchanged; a 4,096-list miss measured 24.09 us before and
24.93 us after. The cache and rate monitor are not on the proxy request path.

A separate 50,000-query UDP loopback run against one process returned 50,000
correct replies with zero failures in 20.13 s. Its process RSS was 6,275,072
bytes at start and 6,496,256 at end/peak. This short run does not establish
24-hour stability or absence of leaks. A production rollout still needs a
longer soak under representative traffic and deployment-specific monitoring.

## 2026-11-20 feed lookup measurements

The new optional threat feed held 10,728 domains during the local test. A
10,728-entry miss in the old public linear evaluator took a median 65.76 us
across five MSVC Release runs. The proxy now builds an immutable hash lookup
when a list is loaded; the public evaluator API remains unchanged.

On the same Windows machine and MSVC Release build, three 2,000-query local
fake-upstream runs with a synthetic 10,728-entry list gave median end-to-end
UDP miss p95 of 0.542 ms before and 0.419 ms after indexing. Median successful
throughput was 3,130 versus 3,781 requests/s; all 12,000 requests succeeded.
Maximum sampled process RSS was 8,368,128 bytes before and 8,744,960 after.
One indexed run was slower than all three baseline runs, so these short runs
show an encouraging median rather than a guaranteed speedup under every load.

A separate 10,000-request test in bursts of 128 returned 10,000/10,000 correct
responses, with p95 10.49 ms and peak process RSS 8,744,960 bytes. It did not
create 10,000 simultaneous clients. A single-process 50,000-query sequential
run returned 50,000/50,000, with RSS 8,495,104 bytes at start and 8,699,904
at end/peak over 9.77 s. Neither run proves 24-hour stability or leak freedom.
Raw outputs are in `../bench/results/feed-lookup-preindex.json`,
`../bench/results/feed-lookup-indexed.json`, `../bench/results/feed-stress-10k.json`, and
`../bench/results/feed-soak-50k.json`.
# Cache result (Windows, MSVC Release, 2026-11-20)

Three 2,000-query runs on the same host used the saved pre-cache binary and
the current binary against the same loopback `cache.example` A-answer fixture
(TTL 2 seconds), one request at a time. Both had 6,000/6,000 successes.
Median p95 RTT changed from 0.375 to 0.158 ms; median throughput from 3,629
to 7,716 queries/s. Maximum sampled process RSS across runs was 7.10 vs
6.41 MB. The Python client and fake upstream contribute to these numbers;
other domains, EDNS and DNSSEC are not covered by this cache measurement.
Raw data: `../bench/results/cache-before.json` and
`../bench/results/cache-after.json`.

