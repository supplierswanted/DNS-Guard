# Reproducible performance checks

Build optimized binaries without sanitizers when measuring performance:

```powershell
cmake -S . -B build-perf -DDNS_BENCHMARKS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-perf --config Release --parallel
.\build-perf\Release\dns_component_bench.exe > components.csv
python .\bench\proxy-allocation.py .\build-perf\Release\dns_allocation_probe.exe > allocations.json
python .\bench\proxy-performance.py --exe .\build-perf\Release\dns_guard.exe --output network.json --rounds 3 --requests 2000
```

With Ninja or Linux, remove the Release subdirectory from executable paths.
These programs use separate random loopback ports and do not change adapter DNS
or contact a public resolver. Production builds have no allocation instrumentation.
Python is required for network measurements, using only its standard library.

## What each measurement means

- component-performance.cpp reports five runs of component CPU cost and requested
  allocation totals for list sizes 0/64/4096/10728, cache size 1024, rate keys 4096 and
  bounded sequential/concurrent collector traffic. Fixture construction is outside
  measurement. The four-producer collector reports attempted enqueues, including
  legitimate capacity drops; read stderr accepted/drop counts before comparing.
- proxy-allocation.cpp replaces ordinary new only in an isolated profiling host.
  It reports requested bytes and allocation calls for a fixed workload, excluding
  startup. These bytes are cumulative allocation traffic, not retained RAM.
- proxy-performance.py reports successful RTT p50/p95/p99, throughput, failures,
  sampled service RSS, and Windows private bytes. The fake upstream runs outside
  the measured service. Delayed-peer scenarios use two workers, queue64/256,
  timeout500/1500, and concurrent 20ms-delayed replies. Queue overflow and timeout
  results are counted; successful RTT percentiles must not conceal failed queries.
  TCP clients reconnect every eight queries. RSS sampling interval is 5ms and can
  miss brief peaks. Allocation counters do not include kernel socket buffers.

Use the same compiler, flags, machine, fixture and benchmark revision for before
and after. Preserve the original source and executable hashes. Run without
concurrent compilers and compare medians across repeated scenarios. Short-run
RSS differences are not proof of leak absence; long-running load and leak
instrumentation remain separate checks. Parser-only historical throughput is
not end-to-end forwarding throughput. Measurements from Windows and Linux must
not be presented as interchangeable.
