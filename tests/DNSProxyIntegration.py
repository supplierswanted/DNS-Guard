"""Offline UDP/TCP integration checks. Usage: python DNSProxyIntegration.py dns_guard"""
import concurrent.futures
import secrets
import contextlib
import os
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


def query(name="example.com", ident=0x1234, qtype=1):
    labels = b"".join(bytes([len(label)]) + label.encode("ascii")
                      for label in name.split(".")) + b"\0"
    return struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def question_name(packet):
    pos, labels = 12, []
    while packet[pos]:
        length = packet[pos]
        labels.append(packet[pos + 1:pos + 1 + length].decode("ascii"))
        pos += length + 1
    return ".".join(labels)


def response(packet, truncated=False):
    flags = 0x8380 if truncated else 0x8180
    additional, = struct.unpack("!H", packet[10:12])
    return packet[:2] + struct.pack("!5H", flags, 1, 0, 0, additional) + packet[12:]


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError("connection closed before the DNS frame finished")
        data.extend(part)
    return bytes(data)


class Upstream:
    """A real, loopback-only UDP/TCP peer with deterministic failure modes."""
    def __init__(self):
        # Avoid Windows' excluded high UDP ranges while reserving both protocols.
        for attempt in range(100):
            self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.tcp.bind(("127.0.0.1", 20000 + secrets.randbelow(20000)))
                self.port = self.tcp.getsockname()[1]
                self.udp.bind(("127.0.0.1", self.port))
                break
            except OSError:
                self.tcp.close()
                self.udp.close()
                if attempt == 99:
                    raise
        self.tcp.listen(8)
        self.udp.settimeout(0.1)
        self.tcp.settimeout(0.1)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.seen = []
        self.errors = []
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.threads = [threading.Thread(target=self.udp_loop),
                        threading.Thread(target=self.tcp_loop)]
        for thread in self.threads:
            thread.start()

    def reply(self, packet, transport):
        name = question_name(packet)
        with self.lock:
            self.seen.append((name, transport, packet[:2]))
        if name == "timeout.example":
            return None
        out = response(packet, name == "truncated.example" and transport == "udp")
        if name == "wrongid.example":
            out = bytes([out[0] ^ 0x80]) + out[1:]
        if name == "wrongname.example":
            out = out[:13] + bytes([out[13] ^ 1]) + out[14:]
        if name == "wrongtype.example":
            out = out[:-4] + struct.pack("!HH", 28, 1)
        if name == "partialtc.example" and transport == "udp":
            # Declare one answer, include only the start of its compressed owner.
            out = response(packet, truncated=True)
            out = out[:6] + struct.pack("!H", 1) + out[8:] + b"\xc0"
        if name == "large.example":
            txt = b"\xff" + b"a" * 255 + b"\xff" + b"b" * 255 + b"\x5a" + b"c" * 90
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt)
        if name == "cache.example":
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH4B", 1, 1, 2, 4, 1, 2, 3, 4))
        if name in ("rebind.example", "rebind-allowed.example"):
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH4B", 1, 1, 60, 4, 127, 0, 0, 1))
        if name == "rebind6.example":
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + b"\0" * 15 + b"\x01")
        if name == "rebind-cname.example":
            inner = b"\x06inside\x07example\0"
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 2, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(inner)) + inner
                   + inner + struct.pack("!HHIH4B", 1, 1, 60, 4, 127, 0, 0, 1))
        if name == "unrelated-private.example":
            other = b"\x05other\x07example\0"
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 2, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH4B", 1, 1, 60, 4, 1, 2, 3, 4)
                   + other + struct.pack("!HHIH4B", 1, 1, 60, 4, 127, 0, 0, 1))
        if name in ("cname-block.example", "cname-allow.example"):
            target = "blocked.example" if name == "cname-block.example" else "conflict.example"
            wire = b"".join(bytes([len(part)]) + part.encode() for part in target.split(".")) + b"\0"
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(wire)) + wire)
        if name == "unrelated-cname.example":
            other = b"\x05other\x07example\0"
            blocked = b"\x07blocked\x07example\0"
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 2, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH4B", 1, 1, 60, 4, 1, 2, 3, 4)
                   + other + struct.pack("!HHIH", 5, 1, 60, len(blocked)) + blocked)
        if name == "reverse-chain.example":
            middle = b"\x06middle\x07example\0"
            blocked = b"\x07blocked\x07example\0"
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 2, 0, 0) + packet[12:]
                   + middle + struct.pack("!HHIH", 5, 1, 60, len(blocked)) + blocked
                   + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(middle)) + middle)
        if name == "ambiguous-cname.example":
            first = b"\x05first\x07example\0"
            blocked = b"\x07blocked\x07example\0"
            out = (packet[:2] + struct.pack("!5H", 0x8180, 1, 2, 0, 0) + packet[12:]
                   + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(first)) + first
                   + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(blocked)) + blocked)
        return out

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                out = self.reply(packet, "udp")
                if out is not None:
                    self.udp.sendto(out, peer)
            except socket.timeout:
                pass
            except Exception as error:
                if not self.stop.is_set():
                    self.errors.append(error)

    def tcp_loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.tcp.accept()
                self.pool.submit(self.tcp_peer, conn)
            except socket.timeout:
                pass
            except OSError:
                if not self.stop.is_set():
                    raise

    def tcp_peer(self, conn):
        with conn:
            conn.settimeout(2)
            try:
                while not self.stop.is_set():
                    size, = struct.unpack("!H", read_exact(conn, 2))
                    out = self.reply(read_exact(conn, size), "tcp")
                    if out is not None:
                        conn.sendall(struct.pack("!H", len(out)) + out)
            except (EOFError, OSError):
                pass
            except Exception as error:
                self.errors.append(error)

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(3)
        self.udp.close()
        self.tcp.close()
        self.pool.shutdown(wait=True)
        if self.errors:
            raise AssertionError(f"fake upstream failed: {self.errors}")


def available_port():
    for attempt in range(100):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                port = 20000 + secrets.randbelow(20000)
                tcp.bind(("127.0.0.1", port))
                udp.bind(("127.0.0.1", port))
                return port
            except OSError:
                if attempt == 99:
                    raise


def available_ipv6_port():
    for attempt in range(100):
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp, \
             socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
            try:
                port = 20000 + secrets.randbelow(20000)
                tcp.bind(("::1", port))
                udp.bind(("::1", port))
                return port
            except OSError:
                if attempt == 99:
                    raise


@contextlib.contextmanager
def proxy(executable, upstream_port, extra=None):
    with tempfile.TemporaryDirectory(prefix="dns-guard-integration-") as directory:
        root = pathlib.Path(directory)
        (root / "deny.txt").write_text("blocked.example\nconflict.example\n", encoding="ascii")
        (root / "allow.txt").write_text("conflict.example\n", encoding="ascii")
        port = available_port()
        config = {
            "listen_ipv4": "127.0.0.1", "listen_port": str(port),
            "upstream_ipv4": "127.0.0.1", "upstream_port": str(upstream_port),
            "timeout_ms": "500", "workers": "4", "queue_capacity": "8",
            "blocklist": str(root / "deny.txt"), "allowlist": str(root / "allow.txt"),
        }
        config.update(extra or {})
        path = root / "guard.conf"
        path.write_text("".join(f"{key}={value}\n" for key, value in config.items()), encoding="ascii")
        with (root / "output.log").open("w+b") as log:
            process = subprocess.Popen([executable, str(path)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(f"proxy exited {process.returncode}: {log.read().decode(errors='replace')}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("proxy did not open its TCP listener")
                        time.sleep(0.02)
                yield port, process
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)


def udp_exchange(port, packet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(packet, ("127.0.0.1", port))
        return sock.recvfrom(65535)[0]


class ProxyIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = Upstream()
        cls.running = proxy(EXECUTABLE, cls.upstream.port)
        try:
            cls.port, cls.process = cls.running.__enter__()
        except BaseException:
            cls.upstream.close()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            cls.running.__exit__(None, None, None)
        finally:
            cls.upstream.close()

    def check_reply(self, packet, answer, rcode=0):
        self.assertGreaterEqual(len(answer), 12)
        self.assertEqual(answer[:2], packet[:2])
        flags, = struct.unpack("!H", answer[2:4])
        self.assertTrue(flags & 0x8000)
        self.assertEqual(flags & 15, rcode)
        self.assertEqual(question_name(answer), question_name(packet))

    def test_udp_forwarding(self):
        packet = query()
        self.check_reply(packet, udp_exchange(self.port, packet))

    def test_secondary_upstream_after_primary_failure(self):
        unreachable = available_port()
        with proxy(EXECUTABLE, unreachable,
                   {"secondary_upstream_ipv4": "127.0.0.1",
                    "secondary_upstream_port": str(self.upstream.port)}) as (port, _):
            packet = query("failover.example")
            self.check_reply(packet, udp_exchange(port, packet))
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                size, = struct.unpack("!H", read_exact(sock, 2))
                self.check_reply(packet, read_exact(sock, size))
        with self.upstream.lock:
            self.assertIn(("failover.example", "udp"),
                          [(name, transport) for name, transport, _ in self.upstream.seen])
            self.assertIn(("failover.example", "tcp"),
                          [(name, transport) for name, transport, _ in self.upstream.seen])

    def test_opt_in_rebinding_protection_and_allowlist(self):
        packet = query("rebind.example")
        self.check_reply(packet, udp_exchange(self.port, packet))
        with tempfile.TemporaryDirectory() as directory:
            allowed = pathlib.Path(directory) / "allowed.txt"
            allowed.write_text("rebind-allowed.example\n", encoding="ascii")
            with proxy(EXECUTABLE, self.upstream.port,
                       {"rebind_protection": "1", "allowlist": str(allowed)}) as (port, _):
                self.check_reply(packet, udp_exchange(port, packet), 5)
                ipv6 = query("rebind6.example", qtype=28)
                self.check_reply(ipv6, udp_exchange(port, ipv6), 5)
                chained = query("rebind-cname.example")
                self.check_reply(chained, udp_exchange(port, chained), 5)
                unrelated = query("unrelated-private.example")
                self.check_reply(unrelated, udp_exchange(port, unrelated))
                excepted = query("rebind-allowed.example")
                self.check_reply(excepted, udp_exchange(port, excepted))

    def test_positive_cache_expires_and_rewrites_id(self):
        first, second = query("cache.example", 0x1234), query("cache.example", 0xabcd)
        with self.upstream.lock:
            before = sum(name == "cache.example" for name, _, _ in self.upstream.seen)
        self.check_reply(first, udp_exchange(self.port, first))
        answer = udp_exchange(self.port, second)
        self.check_reply(second, answer)
        with self.upstream.lock:
            current = sum(name == "cache.example" for name, _, _ in self.upstream.seen)
        self.assertEqual(current - before, 1)
        time.sleep(2.1)
        self.check_reply(second, udp_exchange(self.port, second))
        with self.upstream.lock:
            current = sum(name == "cache.example" for name, _, _ in self.upstream.seen)
        self.assertEqual(current - before, 2)

    def test_optional_ipv6_loopback_udp_tcp(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            ipv6_port = available_ipv6_port()
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        with proxy(EXECUTABLE, self.upstream.port,
                   {"listen_ipv6_port": str(ipv6_port)}) as (ipv4_port, _):
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                for name, code in (("blocked.example", 5), ("ipv6-allowed.example", 0)):
                    packet = query(name)
                    sock.sendto(packet, ("::1", ipv6_port))
                    self.check_reply(packet, sock.recvfrom(65535)[0], code)
            with socket.create_connection(("::1", ipv6_port), timeout=2) as sock:
                sock.settimeout(2)
                packet = query("blocked.example")
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                size, = struct.unpack("!H", read_exact(sock, 2))
                self.check_reply(packet, read_exact(sock, size), 5)
            packet = query()
            self.check_reply(packet, udp_exchange(ipv4_port, packet))

    @unittest.skipUnless(os.name == "nt", "PowerShell probe is Windows-only")
    def test_powershell_probe_ipv6(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            ipv6_port = available_ipv6_port()
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "Test-DNSGuard.ps1"
        with proxy(EXECUTABLE, self.upstream.port, {"listen_ipv6_port": str(ipv6_port)}):
            for transport in ([], ["-Tcp"]):
                for name, status in (("blocked.example", "REFUSED"),
                                     ("ipv6-allowed.example", "NOERROR")):
                    result = subprocess.run(
                        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                         str(script), "-Server", "::1", "-Port", str(ipv6_port),
                         "-Name", name, *transport],
                        capture_output=True, text=True, timeout=8)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(status, result.stdout)

    def test_cname_target_policy(self):
        for name, code in (("cname-block.example", 5), ("cname-allow.example", 0)):
            packet = query(name)
            self.check_reply(packet, udp_exchange(self.port, packet), code)
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                size, = struct.unpack("!H", read_exact(sock, 2))
                self.check_reply(packet, read_exact(sock, size), code)

    def test_unrelated_cname_does_not_block_allowed_answer(self):
        packet = query("unrelated-cname.example")
        self.check_reply(packet, udp_exchange(self.port, packet))

    def test_reversed_cname_chain_still_blocks(self):
        packet = query("reverse-chain.example")
        self.check_reply(packet, udp_exchange(self.port, packet), 5)

    def test_ambiguous_cname_cannot_bypass_policy(self):
        packet = query("ambiguous-cname.example")
        self.check_reply(packet, udp_exchange(self.port, packet), 2)

    def test_large_udp_payload_and_reply_are_bounded(self):
        packet = query("padding.example")
        packet = packet[:10] + b"\x00\x01" + packet[12:]
        padding = struct.pack("!HH", 12, 62000) + bytes(62000)
        packet += b"\0" + struct.pack("!HHIH", 41, 4096, 0, len(padding)) + padding
        answer = udp_exchange(self.port, packet)
        self.check_reply(packet, answer)
        self.assertTrue(answer[2] & 2, "oversized UDP reply must request TCP retry")
        self.assertLessEqual(len(answer), 4096)
        healthy = query()
        self.check_reply(healthy, udp_exchange(self.port, healthy))

    def test_zone_transfer_is_refused(self):
        packet = query("transfer.example")
        packet = packet[:-4] + struct.pack("!HH", 252, 1)
        with self.upstream.lock:
            before = len(self.upstream.seen)
        self.check_reply(packet, udp_exchange(self.port, packet), 5)
        with self.upstream.lock:
            self.assertEqual(before, len(self.upstream.seen))

    def test_tcp_split_frames_and_reuse(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.settimeout(2)
            for ident in (19, 20):
                packet = query(ident=ident)
                frame = struct.pack("!H", len(packet)) + packet
                for part in (frame[:1], frame[1:8], frame[8:]):
                    sock.sendall(part)
                size, = struct.unpack("!H", read_exact(sock, 2))
                self.check_reply(packet, read_exact(sock, size))

    def test_simultaneous_same_client_id(self):
        def exchange(i):
            packet = query(f"client{i}.example", 7)
            answer = udp_exchange(self.port, packet)
            self.check_reply(packet, answer)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(exchange, range(12)))

    def test_block_subdomain_and_allow_override(self):
        for name in ("blocked.example", "child.blocked.example", "CHILD.BLOCKED.EXAMPLE"):
            with self.upstream.lock:
                before = sum(n == name for n, _, _ in self.upstream.seen)
            packet = query(name)
            self.check_reply(packet, udp_exchange(self.port, packet), 5)
            with self.upstream.lock:
                after = sum(n == name for n, _, _ in self.upstream.seen)
            self.assertEqual(before, after, "blocked query reached upstream")
        packet = query("child.conflict.example")
        self.check_reply(packet, udp_exchange(self.port, packet))
        packet = query("CHILD.CONFLICT.EXAMPLE")
        self.check_reply(packet, udp_exchange(self.port, packet))

    def test_blocklist_reload_keeps_last_good_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            blocklist = pathlib.Path(directory) / "deny.txt"
            blocklist.write_text("old-deny.example\n", encoding="ascii")
            with proxy(EXECUTABLE, self.upstream.port, {"blocklist": str(blocklist)}) as (port, process):
                old = query("old-deny.example")
                new = query("new-deny.example")
                self.check_reply(old, udp_exchange(port, old), 5)
                self.check_reply(new, udp_exchange(port, new))
                staged = blocklist.with_suffix(".next")
                staged.write_text("old-deny.example\nnew-deny.example\n", encoding="ascii")
                os.replace(staged, blocklist)
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    if udp_exchange(port, new)[3] & 15 == 5:
                        break
                    time.sleep(0.1)
                self.check_reply(new, udp_exchange(port, new), 5)
                staged.write_text("invalid..name\n", encoding="ascii")
                os.replace(staged, blocklist)
                time.sleep(1.2)
                self.check_reply(new, udp_exchange(port, new), 5)
                self.assertIsNone(process.poll())

    def test_realistic_list_exceeds_old_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            blocklist = pathlib.Path(directory) / "deny.txt"
            blocklist.write_text("".join(f"site{i}.example\n" for i in range(6000)), encoding="ascii")
            with proxy(EXECUTABLE, self.upstream.port, {"blocklist": str(blocklist)}) as (port, _):
                packet = query("site5999.example")
                self.check_reply(packet, udp_exchange(port, packet), 5)

    def test_feedlist_reloads_without_losing_manual_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = pathlib.Path(directory) / "feed.txt"
            feed.write_text("feed-old.example\n", encoding="ascii")
            with proxy(EXECUTABLE, self.upstream.port, {"feedlist": str(feed)}) as (port, _):
                for name in ("blocked.example", "feed-old.example"):
                    packet = query(name)
                    self.check_reply(packet, udp_exchange(port, packet), 5)
                staged = feed.with_suffix(".next")
                staged.write_text("feed-new.example\n", encoding="ascii")
                original = feed.stat()
                os.utime(staged, ns=(original.st_atime_ns, original.st_mtime_ns))
                os.replace(staged, feed)
                packet = query("feed-new.example")
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline and udp_exchange(port, packet)[3] & 15 != 5:
                    time.sleep(0.1)
                self.check_reply(packet, udp_exchange(port, packet), 5)
                manual = query("blocked.example")
                self.check_reply(manual, udp_exchange(port, manual), 5)

    def test_policy_reload_invalidates_cached_answer(self):
        with tempfile.TemporaryDirectory() as directory:
            feed = pathlib.Path(directory) / "feed.txt"
            feed.write_text("# empty\n", encoding="ascii")
            with proxy(EXECUTABLE, self.upstream.port, {"feedlist": str(feed)}) as (port, _):
                packet = query("cache.example")
                self.check_reply(packet, udp_exchange(port, packet))
                self.check_reply(packet, udp_exchange(port, packet))
                staged = feed.with_suffix(".next")
                staged.write_text("cache.example\n", encoding="ascii")
                os.replace(staged, feed)
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline and udp_exchange(port, packet)[3] & 15 != 5:
                    time.sleep(0.1)
                self.check_reply(packet, udp_exchange(port, packet), 5)

    @unittest.skipUnless(os.name == "nt", "Windows updater is PowerShell-only")
    def test_updater_changes_live_feed_and_rolls_back(self):
        script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "Update-DNSBlocklist.ps1"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            feed, source = root / "feed.txt", root / "source.txt"
            feed.write_text("old-feed.example\n", encoding="ascii")
            source.write_text("new-feed.example\n", encoding="ascii")
            with proxy(EXECUTABLE, self.upstream.port, {"feedlist": str(feed)}) as (port, _):
                result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                                         "-File", str(script), "-Destination", str(feed),
                                         "-SourceFile", str(source), "-MinEntries", "1"],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                packet = query("new-feed.example")
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline and udp_exchange(port, packet)[3] & 15 != 5:
                    time.sleep(0.1)
                self.check_reply(packet, udp_exchange(port, packet), 5)
                result = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                                         "-File", str(script), "-Destination", str(feed), "-Rollback"],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                old = query("old-feed.example")
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline and udp_exchange(port, old)[3] & 15 != 5:
                    time.sleep(0.1)
                self.check_reply(old, udp_exchange(port, old), 5)

    def test_mismatched_upstream_answers(self):
        for name in ("wrongid.example", "wrongname.example", "wrongtype.example"):
            packet = query(name)
            self.check_reply(packet, udp_exchange(self.port, packet), 2)

    def test_upstream_timeout(self):
        packet = query("timeout.example")
        start = time.monotonic()
        self.check_reply(packet, udp_exchange(self.port, packet), 2)
        self.assertLess(time.monotonic() - start, 2)

    def test_udp_truncation_uses_tcp(self):
        for name in ("truncated.example", "partialtc.example"):
            packet = query(name)
            self.check_reply(packet, udp_exchange(self.port, packet))
            with self.upstream.lock:
                self.assertIn((name, "tcp"), [(n, t) for n, t, _ in self.upstream.seen])

    def test_malformed_udp_does_not_crash(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for packet in (b"", b"\0", query()[:-1], b"\0" * 65507):
                sock.sendto(packet, ("127.0.0.1", self.port))
        packet = query()
        self.check_reply(packet, udp_exchange(self.port, packet))
        self.assertIsNone(self.process.poll())

    def test_large_response_obeys_udp_limit(self):
        packet = query("large.example")
        answer = udp_exchange(self.port, packet)
        self.check_reply(packet, answer)
        self.assertLessEqual(len(answer), 512)
        self.assertTrue(struct.unpack("!H", answer[2:4])[0] & 0x0200)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            size, = struct.unpack("!H", read_exact(sock, 2))
            self.assertGreater(size, 512)
            self.check_reply(packet, read_exact(sock, size))

    def test_incomplete_tcp_is_bounded(self):
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(b"\xff\xff")
            try:
                result = sock.recv(2)
                self.assertEqual(result, b"")
            except ConnectionResetError:
                pass

    def test_unreachable_upstream(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
        with proxy(EXECUTABLE, port) as (local, _):
            packet = query()
            self.check_reply(packet, udp_exchange(local, packet), 2)

    def test_resource_limits_and_recovery(self):
        with proxy(EXECUTABLE, self.upstream.port, {"workers": "1", "queue_capacity": "1"}) as (port, process):
            sockets = []
            try:
                for _ in range(12):
                    try:
                        sock = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                    except (ConnectionRefusedError, TimeoutError):
                        continue  # Rejecting excess clients is valid overload behavior.
                    sockets.append(sock)
                    try:
                        sock.sendall(b"\xff\xff")
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                self.assertTrue(sockets, "no overload client connected")
                time.sleep(1.2)
            finally:
                for sock in sockets:
                    sock.close()
            self.assertIsNone(process.poll())
            packet = query()
            self.check_reply(packet, udp_exchange(port, packet))

    def test_invalid_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "invalid.conf"
            for line in ("listen_ipv4=0.0.0.0", "workers=0", "workers=-1", "workers=33",
                         "queue_capacity=257", "timeout_ms=99", "timeout_ms=10001",
                         "upstream_port=65536", "unknown_key=1", "workers=2\nworkers=3",
                         "upstream_ipv4=not-an-address", "secondary_upstream_ipv4=0.0.0.0",
                         "secondary_upstream_ipv4=not-an-address", "secondary_upstream_port=65536",
                         "secondary_upstream_port=5354", "no-equals-sign"):
                prefix = "" if line.startswith("upstream_ipv4=") else "upstream_ipv4=127.0.0.1\n"
                path.write_text(prefix + line + "\n", encoding="ascii")
                completed = subprocess.run([EXECUTABLE, str(path)], capture_output=True, timeout=3)
                self.assertNotEqual(completed.returncode, 0, line)
            path.write_text("upstream_ipv4=127.0.0.1\n#" + "x" * 65536, encoding="ascii")
            completed = subprocess.run([EXECUTABLE, str(path)], capture_output=True, timeout=3)
            self.assertNotEqual(completed.returncode, 0, "oversized configuration")
            blocklist = pathlib.Path(directory) / "oversized.txt"
            blocklist.write_bytes(b"#" + b"x" * (4 * 1024 * 1024))
            path.write_text(f"upstream_ipv4=127.0.0.1\nblocklist={blocklist}\n", encoding="ascii")
            completed = subprocess.run([EXECUTABLE, str(path)], capture_output=True, timeout=3)
            self.assertNotEqual(completed.returncode, 0, "oversized blocklist")
            self.assertIn(b"too large", completed.stderr)

    @unittest.skipIf(os.name == "nt", "Windows controlled stop is verified through SCM/console separately")
    def test_shutdown_with_incomplete_client(self):
        with proxy(EXECUTABLE, self.upstream.port) as (port, process):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.sendall(b"\xff\xff")
                start = time.monotonic()
                process.terminate()
                self.assertEqual(process.wait(timeout=3), 0)
                self.assertLess(time.monotonic() - start, 3)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: DNSProxyIntegration.py /path/to/dns_guard")
    EXECUTABLE = str(pathlib.Path(sys.argv.pop()).resolve())
    unittest.main(verbosity=2)
