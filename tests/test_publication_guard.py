from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
SCANNER = REPOSITORY / "scripts" / "publication_guard.py"


class PublicationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(SCANNER), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_hash_only_scan_does_not_disclose_private_term(self) -> None:
        private_term = "controller-internal-identifier"
        denylist = self.root / "denylist.txt"
        denylist.write_text(private_term + "\n", encoding="utf-8")
        denylist.chmod(0o600)
        hashes = self.root / "hashes.txt"
        generated = self.invoke(
            "--denylist",
            str(denylist),
            "--write-hashes",
            str(hashes),
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertNotIn(private_term, hashes.read_text(encoding="ascii"))
        candidate = self.root / "candidate.txt"
        candidate.write_text(private_term + "\n", encoding="utf-8")
        scanned = self.invoke("--hash-file", str(hashes), str(candidate))
        self.assertEqual(scanned.returncode, 1)
        self.assertIn("private denylist hash match", scanned.stderr)
        self.assertNotIn(private_term, scanned.stderr)

    def test_rejects_secret_assignment_and_unsafe_url(self) -> None:
        candidate = self.root / "candidate.txt"
        assignment = "secret" + "=not-for-publication"
        url = "http" + "://example.invalid/controller"
        candidate.write_text(f"{assignment}\n{url}\n", encoding="utf-8")
        result = self.invoke(str(candidate))
        self.assertEqual(result.returncode, 1)
        self.assertIn("credential assignment", result.stderr)
        self.assertIn("unsafe cleartext URL", result.stderr)

    def test_rejects_runtime_state_path_with_harmless_content(self) -> None:
        candidate = self.root / "state.json"
        candidate.write_text("{}\n", encoding="utf-8")
        result = self.invoke(str(candidate))
        self.assertEqual(result.returncode, 1)
        self.assertIn("runtime credential state", result.stderr)


if __name__ == "__main__":
    unittest.main()
