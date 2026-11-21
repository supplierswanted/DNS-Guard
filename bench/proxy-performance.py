"""Loopback-only end-to-end benchmark; Python/fake-peer overhead is included."""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import secrets
import selectors
import socket
import statistics
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tests"))
from DNSProxyIntegration import Upstream, proxy, query, read_exact


def memory(pid):
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                    "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        psapi.GetProcessMemoryInfo.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD)
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            values = Counters()
            values.cb = ctypes.sizeof(values)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(values), values.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            return {"rss_bytes": values.WorkingSetSize, "private_bytes": values.PrivateUsage}
        finally:
            kernel.CloseHandle(handle)
    values = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            values["rss_bytes"] = int(line.split()[1]) * 1024
    if "rss_bytes" not in values:
        raise RuntimeError("VmRSS unavailable")
    values["private_bytes"] = None
    return values


class MemorySampler:
    def __init__(self, pid):
        self.pid, self.samples, self.errors = pid, [], []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)

    def record(self):
        self.samples.append({"monotonic_seconds": time.monotonic(), **memory(self.pid)})

    def run(self):
        while not self.stop.wait(0.005):
            try:
                self.record()
            except (OSError, RuntimeError) as error:
                self.errors.append(str(error))
                return

    def __enter__(self):
        self.record()
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()
        self.record()
        if self.errors:
            raise RuntimeError(self.errors)


class Peer(Upstream):
    def __init__(self, delay=0):
        self.delay = delay
        # Use the integration test's bounded range; Windows may reserve its
        # ephemeral TCP range for UDP, causing repeated port-0 bind failures.
        for attempt in range(100):
            try:
                self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.tcp.bind(("127.0.0.1", 20000 + secrets.randbelow(20000)))
                self.port = self.tcp.getsockname()[1]
                self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp.bind(("127.0.0.1", self.port))
                self.tcp.listen(8)
                break
            except OSError:
                for name in ("udp", "tcp"):
                    sock = getattr(self, name, None)
                    if sock is not None:
                        sock.close()
                if attempt == 99:
                    raise
        self.udp.settimeout(0.1)
        self.tcp.settimeout(0.1)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.seen, self.errors = [], []
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.threads = [threading.Thread(target=self.udp_loop), threading.Thread(target=self.tcp_loop)]
        for thread in self.threads:
            thread.start()

    def send_udp(self, packet, address):
        try:
            if self.delay:
                time.sleep(self.delay)
            answer = self.reply(packet, "udp")
            if answer is not None:
                self.udp.sendto(answer, address)
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, address = self.udp.recvfrom(65535)
                if self.delay:
                    self.pool.submit(self.send_udp, packet, address)
                else:
                    self.send_udp(packet, address)
            except socket.timeout:
                pass
            except ConnectionResetError:
                # A deliberately expired proxy UDP socket can cause an ICMP
                # port-unreachable notification on this unconnected Windows peer.
                continue
            except OSError:
                if not self.stop.is_set():
                    raise


def valid_answer(packet, answer, expected_code):
    return (len(answer) >= 12 and answer[:2] == packet[:2]
            and bool(answer[2] & 0x80) and answer[3] & 15 == expected_code
            and answer[12:len(packet)] == packet[12:])


def udp_batch(port, names, first_id, expected_code, client_timeout):
    """Send the complete burst first, then multiplex replies on one client thread."""
    selector = selectors.DefaultSelector()
    pending, latencies, errors = {}, [], {}
    try:
        for number, name in enumerate(names):
            packet = query(name, (first_id + number) & 65535)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            start = time.perf_counter()
            try:
                sock.sendto(packet, ("127.0.0.1", port))
            except OSError:
                sock.close()
                errors["send_error"] = errors.get("send_error", 0) + 1
                continue
            pending[sock] = (packet, start)
            selector.register(sock, selectors.EVENT_READ)
        while pending:
            for key, _ in selector.select(0.01):
                sock = key.fileobj
                packet, start = pending.pop(sock)
                try:
                    answer = sock.recv(65535)
                    if valid_answer(packet, answer, expected_code):
                        latencies.append((time.perf_counter() - start) * 1000)
                    else:
                        code = answer[3] & 15 if len(answer) >= 12 else "short"
                        label = f"unexpected_response_{code}"
                        errors[label] = errors.get(label, 0) + 1
                except OSError:
                    errors["receive_error"] = errors.get("receive_error", 0) + 1
                selector.unregister(sock)
                sock.close()
            now = time.perf_counter()
            for sock, (_, start) in list(pending.items()):
                if now - start >= client_timeout:
                    pending.pop(sock)
                    selector.unregister(sock)
                    sock.close()
                    errors["client_timeout"] = errors.get("client_timeout", 0) + 1
        return latencies, errors
    finally:
        for sock in pending:
            sock.close()
        selector.close()


def tcp_run(port, count):
    latencies, errors = [], {}
    for offset in range(0, count, 8):
        sock = None
        try:
            for i in range(offset, min(offset + 8, count)):
                packet = query("example.com", i & 65535)
                start = time.perf_counter()
                if sock is None:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
                    sock.settimeout(2)
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                size, = struct.unpack("!H", read_exact(sock, 2))
                if valid_answer(packet, read_exact(sock, size), 0):
                    latencies.append((time.perf_counter() - start) * 1000)
                else:
                    errors["unexpected_response"] = errors.get("unexpected_response", 0) + 1
        except (OSError, EOFError):
            remaining = min(offset + 8, count) - i
            errors["connection_failure_or_not_attempted"] = (
                errors.get("connection_failure_or_not_attempted", 0) + remaining)
        finally:
            if sock is not None:
                sock.close()
    return latencies, errors


def percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * p
    low = int(index)
    return ordered[low] + (ordered[min(low + 1, len(ordered) - 1)] - ordered[low]) * (index - low)


def scenario(exe, name, requests, transport="udp", delay=0, capacity=64,
             timeout=500, large_list=False, blocked=False, burst=1, list_size=None,
             qname=None):
    upstream = Peer(delay)
    try:
        with tempfile.TemporaryDirectory(prefix="dns-guard-bench-lists-") as directory:
            root = pathlib.Path(directory)
            denied = root / "denied.txt"
            allowed = root / "allowed.txt"
            entries = list_size or (4096 if large_list else 1)
            denied.write_text("".join(f"entry{i:04}.example\n" for i in range(entries - 1))
                              + "blocked.example\n", encoding="ascii")
            allowed.write_text("", encoding="ascii")
            config = {"queue_capacity": str(capacity), "workers": "2" if delay else "4",
                      "timeout_ms": str(timeout), "blocklist": str(denied), "allowlist": str(allowed)}
            with proxy(exe, upstream.port, config) as (port, process):
                latencies, errors = [], {}
                # Warm the normal execution path before the measured sample.
                target = qname or ("blocked.example" if blocked else "example.com")
                warm = query(target)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sock.sendto(warm, ("127.0.0.1", port))
                    sock.recv(65535)
                with MemorySampler(process.pid) as sampler:
                    start = time.perf_counter()
                    if transport == "tcp":
                        latencies, errors = tcp_run(port, requests)
                    else:
                        for offset in range(0, requests, burst):
                            batch = [target] * min(burst, requests - offset)
                            times, bad = udp_batch(port, batch, offset, 5 if blocked else 0,
                                                   timeout / 1000 + 0.75)
                            latencies.extend(times)
                            for key, count in bad.items():
                                errors[key] = errors.get(key, 0) + count
                    elapsed = time.perf_counter() - start
                if process.poll() is not None:
                    raise RuntimeError("proxy exited during measurement")
                rss = [sample["rss_bytes"] for sample in sampler.samples]
                private = [sample["private_bytes"] for sample in sampler.samples
                           if sample["private_bytes"] is not None]
                return {"scenario": name, "requests": requests, "successful": len(latencies),
                        "failed": sum(errors.values()), "errors": errors,
                        "elapsed_seconds": elapsed, "successful_per_second": len(latencies) / elapsed,
                        "latency_ms": {"p50": percentile(latencies, 0.50), "p95": percentile(latencies, 0.95),
                                       "p99": percentile(latencies, 0.99)},
                        "rss_before_bytes": rss[0], "rss_after_bytes": rss[-1], "rss_peak_bytes": max(rss),
                        "private_peak_bytes": max(private) if private else None,
                        "memory_samples": sampler.samples,
                        "config": {"workers": 2 if delay else 4, "queue_capacity": capacity,
                                   "timeout_ms": timeout, "list_entries": entries,
                                   "burst": burst, "upstream_reply_delay_ms": delay * 1000,
                                   "request_payload_bytes": len(query(target))}}
    finally:
        upstream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--only-cache", action="store_true",
                        help="measure repeated positive A answers only")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 10 or not 1 <= args.requests <= 100000:
        parser.error("rounds must be 1..10; requests must be 1..100000")
    exe = str(pathlib.Path(args.exe).resolve())
    result = {"environment": {"platform": platform.platform(), "python": sys.version,
                              "cpu": platform.processor(), "cpu_count": os.cpu_count(),
                              "executable_sha256": hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest()},
              "method": "Loopback fake peer only; no provider traffic. Python client, scheduling and fake-peer overhead included. "
                        "TCP reconnects every 8 queries. Queue scenarios send one burst before multiplexed receive; "
                        "memory is the proxy process only, sampled every 5ms (brief peaks can be missed). "
                        "Latency percentiles include only successful expected-RCODE replies; failures are counted separately. "
                        "Queue scenarios use two proxy workers and a peer with concurrent 20ms delayed replies.",
              "rounds": [], "summaries": {}}
    for round_index in range(args.rounds):
        cases = [
            dict(name="udp_forward", requests=args.requests),
            dict(name="udp_block", requests=args.requests, blocked=True),
            dict(name="tcp_forward", requests=args.requests, transport="tcp"),
            dict(name="list4096_miss", requests=args.requests, large_list=True),
            dict(name="list4096_block", requests=args.requests, large_list=True, blocked=True),
        ]
        if args.only_cache:
            cases = [dict(name="udp_cache_hit", requests=args.requests, qname="cache.example")]
        else:
            for capacity in (64, 256):
                for timeout in (500, 1500):
                    cases.append(dict(name=f"queue{capacity}_timeout{timeout}", requests=capacity + 10,
                                      delay=0.02, capacity=capacity, timeout=timeout, burst=capacity + 10))
        for case in cases:
            measured = scenario(exe, **case)
            measured["round"] = round_index + 1
            result["rounds"].append(measured)
            print(json.dumps({key: value for key, value in measured.items() if key != "memory_samples"}), flush=True)
        pathlib.Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    for name in sorted({row["scenario"] for row in result["rounds"]}):
        rows = [row for row in result["rounds"] if row["scenario"] == name]
        result["summaries"][name] = {
            "median_successful_per_second": statistics.median(row["successful_per_second"] for row in rows),
            "total_successful": sum(row["successful"] for row in rows),
            "total_failed": sum(row["failed"] for row in rows),
            "median_p50_ms": statistics.median(row["latency_ms"]["p50"] for row in rows
                                              if row["latency_ms"]["p50"] is not None),
            "median_p95_ms": statistics.median(row["latency_ms"]["p95"] for row in rows
                                              if row["latency_ms"]["p95"] is not None),
            "median_p99_ms": statistics.median(row["latency_ms"]["p99"] for row in rows
                                              if row["latency_ms"]["p99"] is not None),
            "max_rss_peak_bytes": max(row["rss_peak_bytes"] for row in rows)}
    pathlib.Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
