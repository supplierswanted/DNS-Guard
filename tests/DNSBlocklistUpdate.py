"""Exercise the Windows updater against real local files, without network or service changes."""
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "Update-DNSBlocklist.ps1"


def update(*arguments):
    return subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                           "-File", str(SCRIPT), *map(str, arguments)],
                          capture_output=True, text=True, timeout=15)


class BlocklistUpdate(unittest.TestCase):
    def test_normalize_deduplicate_and_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            destination, source = root / "feed.txt", root / "source.txt"
            destination.write_text("old.example\n", encoding="ascii")
            source.write_text("# comment\nBlocked.Example.\nblocked.example\nother.example\n", encoding="ascii")
            result = update("-Destination", destination, "-SourceFile", source, "-MinEntries", 1)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_text(encoding="ascii"),
                             "blocked.example\nother.example\n")
            result = update("-Destination", destination, "-Rollback")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_text(encoding="ascii"), "old.example\n")

    def test_invalid_update_preserves_previous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            destination, source = root / "feed.txt", root / "source.txt"
            destination.write_text("old.example\n", encoding="ascii")
            source.write_text("bad..example\n", encoding="ascii")
            result = update("-Destination", destination, "-SourceFile", source, "-MinEntries", 1)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_text(encoding="ascii"), "old.example\n")

    def test_rollback_restores_last_successful_update(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            destination, source = root / "feed.txt", root / "source.txt"
            destination.write_text("original.example\n", encoding="ascii")
            for name in ("first.example", "second.example"):
                source.write_text(name + "\n", encoding="ascii")
                result = update("-Destination", destination, "-SourceFile", source, "-MinEntries", 1)
                self.assertEqual(result.returncode, 0, result.stderr)
            result = update("-Destination", destination, "-Rollback")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_text(encoding="ascii"), "first.example\n")

    def test_http_source_is_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory) / "feed.txt"
            destination.write_text("old.example\n", encoding="ascii")
            result = update("-Destination", destination, "-SourceUrl", "http://example.com/feed.txt")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_text(encoding="ascii"), "old.example\n")

    def test_ip_literals_are_not_domains(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            destination, source = root / "feed.txt", root / "source.txt"
            destination.write_text("old.example\n", encoding="ascii")
            source.write_text("1.2.3.4\n2001:db8::1\nblocked.example\n", encoding="ascii")
            result = update("-Destination", destination, "-SourceFile", source, "-MinEntries", 1)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_text(encoding="ascii"), "blocked.example\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
