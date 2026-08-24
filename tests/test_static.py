from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class StaticControllerTests(unittest.TestCase):
    def test_jlab_check_passes_without_podman(self) -> None:
        result = subprocess.run(
            [str(REPOSITORY / "scripts" / "jlab"), "check"],
            cwd=REPOSITORY,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "static controller checks passed\n")

    def test_program_constants_are_exact(self) -> None:
        versions = json.loads(
            (REPOSITORY / "config" / "versions.json").read_text(encoding="utf-8")
        )
        self.assertEqual(versions["controller"]["tag"], "2.568.1-jdk21")
        self.assertEqual(
            versions["controller"]["image"], "docker.io/jenkins/jenkins"
        )
        self.assertEqual(
            versions["controller"]["amd64_digest"],
            "sha256:8279be0a0ed95ad3b67c8677b9e03ff322f61338d39244234a907e9039ac3683",
        )
        self.assertEqual(versions["remoting"]["version"], "3384.v60d89463d9e0")
        self.assertEqual(
            versions["remoting"]["sha256"],
            "2eba7803ff8f59d25b6cac7c13f4f99d39ed6173bf011f8b781b35d0a5e76f19",
        )
        self.assertEqual(
            versions["local_image"], "localhost/jenkins-controller:lab-local"
        )

    def test_controller_has_no_public_or_tcp_agent_binding(self) -> None:
        controllerfile = (REPOSITORY / "Controllerfile").read_text(encoding="utf-8")
        casc = (REPOSITORY / "casc" / "jenkins.yaml").read_text(encoding="utf-8")
        combined = controllerfile + casc
        self.assertIn(
            "COPY plugins.lock /usr/share/jenkins/ref/plugins.lock.txt",
            controllerfile,
        )
        self.assertIn(
            "--plugin-file /usr/share/jenkins/ref/plugins.lock.txt",
            controllerfile,
        )
        self.assertNotIn("0.0.0.0", combined)
        self.assertNotIn("50000", combined)
        self.assertIn("slaveAgentPort: -1", casc)
        self.assertIn("numExecutors: 0", casc)
        self.assertIn('url: "http://127.0.0.1:18080/"', casc)
        self.assertIn(
            "${trim:${readFile:/run/secrets/jlab-admin-password}}", casc
        )

    def test_plugin_files_are_unique_versioned_and_complete(self) -> None:
        def versions(path: Path) -> dict[str, str]:
            result: dict[str, str] = {}
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line or line.startswith("#"):
                    continue
                name, version = line.split(":", 1)
                self.assertTrue(version)
                self.assertNotIn(name, result)
                result[name] = version
            return result

        requested = versions(REPOSITORY / "plugins.requested.txt")
        locked = versions(REPOSITORY / "plugins.lock")
        checksum_names = {
            line.split("  ", 1)[1].removesuffix(".jpi")
            for line in (REPOSITORY / "plugins.sha256")
            .read_text(encoding="ascii")
            .splitlines()
            if line
        }
        self.assertEqual(len(requested), 3)
        self.assertTrue(requested.items() <= locked.items())
        self.assertEqual(set(locked), checksum_names)

    def test_refresh_uses_the_pinned_image_plugin_manager(self) -> None:
        refresh = (REPOSITORY / "scripts" / "refresh-plugins").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'controller_image="docker.io/jenkins/jenkins@$controller_digest"',
            refresh,
        )
        self.assertIn("--entrypoint /bin/jenkins-plugin-cli", refresh)
        self.assertIn("--env HOME=/tmp", refresh)
        self.assertIn("--latest=true", refresh)


if __name__ == "__main__":
    unittest.main()
