from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
GENERATOR = REPOSITORY / "scripts" / "plugin_lock.py"


class PluginLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plugins = self.root / "plugins"
        self.plugins.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def plugin(self, name: str, version: str) -> Path:
        path = self.plugins / f"{name}.jpi"
        manifest = (
            "Manifest-Version: 1.0\n"
            f"Short-Name: {name}\n"
            f"Plugin-Version: {version}\n\n"
        )
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", manifest)
        return path

    def invoke(self) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        lock = self.root / "plugins.lock"
        checksums = self.root / "plugins.sha256"
        result = subprocess.run(
            [
                str(GENERATOR),
                "--plugin-dir",
                str(self.plugins),
                "--lock",
                str(lock),
                "--checksums",
                str(checksums),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return result, lock, checksums

    def test_generates_sorted_lock_and_artifact_checksums(self) -> None:
        beta = self.plugin("beta", "2.0")
        alpha = self.plugin("alpha", "1.0")
        result, lock, checksums = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(lock.read_text(encoding="utf-8"), "alpha:1.0\nbeta:2.0\n")
        expected = (
            f"{hashlib.sha256(alpha.read_bytes()).hexdigest()}  alpha.jpi\n"
            f"{hashlib.sha256(beta.read_bytes()).hexdigest()}  beta.jpi\n"
        )
        self.assertEqual(checksums.read_text(encoding="ascii"), expected)

    def test_rejects_filename_and_short_name_mismatch(self) -> None:
        path = self.plugins / "wrong.jpi"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nShort-Name: actual\nPlugin-Version: 1\n\n",
            )
        result, _, _ = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match Short-Name", result.stderr)

    def test_rejects_empty_plugin_directory(self) -> None:
        result, _, _ = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("contains no .jpi artifacts", result.stderr)


if __name__ == "__main__":
    unittest.main()
