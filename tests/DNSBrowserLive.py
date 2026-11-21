"""Opt-in real browser DNS route check; requires installed Guard and Windows DNS events."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid


def check(browser, executable, monitor, config, blocked_parent):
    name = f"browser-{uuid.uuid4().hex}.{blocked_parent}"
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        output, errors = root / "monitor.out", root / "monitor.err"
        profile = root / "profile"
        profile.mkdir()
        with output.open("wb") as out, errors.open("wb") as err:
            watcher = subprocess.Popen([str(monitor), str(config)], stdout=out, stderr=err)
            process = None
            try:
                time.sleep(1)
                if watcher.poll() is not None:
                    raise RuntimeError(f"DNS monitor exited: {errors.read_text(errors='replace')}")
                url = f"http://{name}/"
                if browser == "Edge":
                    command = [str(executable), "--headless=new", "--disable-gpu", "--no-first-run",
                               f"--user-data-dir={profile}", "--dump-dom", url]
                else:
                    command = [str(executable), "-headless", "-no-remote", "-profile", str(profile),
                               "-screenshot", str(root / "page.png"), url]
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if f"domain={name} " in output.read_text(errors="replace"):
                        line = next(line for line in output.read_text(errors="replace").splitlines()
                                    if f"domain={name} " in line)
                        if "list=DENY" not in line:
                            raise AssertionError(f"{browser}: DNS event did not match blocklist: {line}")
                        print(f"{browser}: {line}")
                        return
                    time.sleep(0.2)
                raise AssertionError(f"{browser}: no Windows DNS event for {name}; "
                                     "browser DoH bypass or browser did not request DNS")
            finally:
                if process and process.poll() is None:
                    subprocess.run(["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                    process.wait(timeout=5)
                    time.sleep(1)
                if watcher.poll() is None:
                    watcher.terminate()
                    watcher.wait(timeout=5)


def main():
    monitor = pathlib.Path(sys.argv[1])
    config = pathlib.Path(sys.argv[2])
    feed = config.parent / "feed.txt"
    blocked_parent = next(line.strip() for line in feed.read_text(encoding="utf-8").splitlines()
                          if line.strip() and not line.startswith("#"))
    system = pathlib.Path(os.environ["ProgramFiles(x86)"])
    candidates = [
        ("Edge", system / "Microsoft/Edge/Application/msedge.exe"),
        ("Firefox", pathlib.Path(os.environ["ProgramFiles"]) / "Mozilla Firefox/firefox.exe"),
    ]
    for browser, executable in candidates:
        if executable.is_file():
            check(browser, executable, monitor, config, blocked_parent)
        else:
            print(f"{browser}: not installed at {executable}")


if __name__ == "__main__":
    main()
