"""Profile total allocations for a fixed number of requests, excluding startup."""
import json
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tests"))
from DNSProxyIntegration import Upstream, available_port, query, udp_exchange


def run(executable, count=1000):
    upstream = Upstream()
    results = []
    try:
        for blocked in (False, True):
            for repeat in range(3):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    (root / "deny.txt").write_text("example.com\n" if blocked else "")
                    port = available_port()
                    config = root / "guard.conf"
                    config.write_text(f"upstream_ipv4=127.0.0.1\nupstream_port={upstream.port}\n"
                                      f"listen_port={port}\nblocklist=deny.txt\n")
                    child = subprocess.Popen([executable, str(config)], stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        if child.stdout.readline().strip() != "READY":
                            raise RuntimeError("allocation probe failed to start")
                        for i in range(count):
                            packet = query(ident=i)
                            answer = udp_exchange(port, packet)
                            if answer[:2] != packet[:2] or (answer[3] & 15) != (5 if blocked else 0):
                                raise RuntimeError("invalid benchmark answer")
                        stdout, stderr = child.communicate("\n", timeout=5)
                        if child.returncode:
                            raise RuntimeError(stderr)
                        stats = dict(item.split("=") for item in stdout.split())
                        results.append({"scenario": "blocked" if blocked else "forward",
                                        "repeat": repeat, "requests": count,
                                        **{k: int(v) for k, v in stats.items()}})
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.wait(timeout=5)
    finally:
        upstream.close()
    return results


if __name__ == "__main__":
    print(json.dumps(run(str(pathlib.Path(sys.argv[1]).resolve())), indent=2))
