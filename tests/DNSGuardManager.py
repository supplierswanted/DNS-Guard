"""Read-only checks for the Windows management entry point."""
import pathlib
import subprocess
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "dns-guard.ps1"


class Manager(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                               "-File", str(SCRIPT), *args], capture_output=True,
                              text=True, timeout=12)

    def test_status_is_read_only(self):
        result = self.invoke("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("RogerfabDNSGuard", result.stdout)

    def test_unknown_command_rejected(self):
        result = self.invoke("unexpected")
        self.assertNotEqual(result.returncode, 0)

    def test_install_requires_elevation(self):
        result = self.invoke("install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Administrator", result.stderr + result.stdout)

    def test_management_scripts_parse(self):
        root = SCRIPT.parent
        scripts = [SCRIPT, root / "scripts" / "Remove-DNSGuard.ps1"]
        command = "$errors=$null; foreach($file in @(" + ",".join(
            "'" + str(path).replace("'", "''") + "'" for path in scripts
        ) + ")) { $tokens=$null; [Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors) | Out-Null }; if($errors){$errors | Write-Error; exit 1}"
        result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", command],
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
