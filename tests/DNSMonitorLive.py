"""Opt-in test against the actual Windows DNS Client event channel."""
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


def main():
    executable, config = sys.argv[1:]
    blocked = f"live-{uuid.uuid4().hex}.blocked.example"
    with tempfile.TemporaryDirectory() as directory:
        output = pathlib.Path(directory) / "monitor.out"
        errors = pathlib.Path(directory) / "monitor.err"
        with output.open("wb") as out, errors.open("wb") as err:
            process = subprocess.Popen([executable, config], stdout=out, stderr=err)
            try:
                time.sleep(1)
                if process.poll() is not None:
                    raise AssertionError(f"monitor exited early: {errors.read_text(errors='replace')}")
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                     f"Resolve-DnsName '{blocked}' -Type A -ErrorAction SilentlyContinue | Out-Null"],
                    timeout=8, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    lines = output.read_text(errors="replace")
                    if f"domain={blocked} " in lines and "list=DENY" in lines:
                        return
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
                raise AssertionError(
                    f"no live DENY event for {blocked}; monitor={output.read_text(errors='replace')[-1000:]} "
                    f"error={errors.read_text(errors='replace')[-500:]}")
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)


if __name__ == "__main__":
    main()
