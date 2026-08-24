#!/usr/bin/env python3
"""Portable command-line entry point for the disposable Jenkins lab."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


EXIT_CONFIGURATION = 20
EXPECTED = {
    "controller": {
        "amd64_digest": "sha256:8279be0a0ed95ad3b67c8677b9e03ff322f61338d39244234a907e9039ac3683",
        "image": "docker.io/jenkins/jenkins",
        "tag": "2.568.1-jdk21",
    },
    "local_image": "localhost/jenkins-controller:lab-local",
    "remoting": {
        "sha256": "2eba7803ff8f59d25b6cac7c13f4f99d39ed6173bf011f8b781b35d0a5e76f19",
        "version": "3384.v60d89463d9e0",
    },
}
RUNTIME_NAMES = {
    "credentials.xml",
    "state.json",
    "initialAdminPassword",
    "secret.key",
}


class CheckFailure(Exception):
    pass


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def versioned_lines(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        require(":" in line, f"{path.name}: unversioned plugin line")
        name, version = line.split(":", 1)
        require(bool(re.fullmatch(r"[a-z0-9][a-z0-9-]*", name)), f"{path.name}: invalid plugin name")
        require(bool(version) and not version.isspace(), f"{path.name}: missing plugin version")
        require(name not in values, f"{path.name}: duplicate plugin {name}")
        values[name] = version
        lines.append(line)
    require(lines == sorted(lines), f"{path.name}: lines must be sorted")
    require(bool(values), f"{path.name}: plugin set is empty")
    return values


def checksum_lines(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    lines = []
    pattern = re.compile(r"([0-9a-f]{64})  ([a-z0-9][a-z0-9-]*)\.jpi")
    for raw_line in path.read_text(encoding="ascii").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = pattern.fullmatch(line)
        require(match is not None, f"{path.name}: invalid checksum line")
        checksum, name = match.groups()
        require(name not in values, f"{path.name}: duplicate plugin {name}")
        values[name] = checksum
        lines.append(line)
    require(lines == sorted(lines, key=lambda item: item.split("  ", 1)[1]), f"{path.name}: lines must be sorted by artifact")
    return values


def check_plugins(root: Path) -> None:
    requested = versioned_lines(root / "plugins.requested.txt")
    locked = versioned_lines(root / "plugins.lock")
    checksums = checksum_lines(root / "plugins.sha256")
    for name, version in requested.items():
        require(locked.get(name) == version, f"plugins.lock does not satisfy requested {name}:{version}")
    require(set(locked) == set(checksums), "plugins.sha256 must cover the complete plugin lock")


def check_controllerfile(root: Path) -> None:
    content = (root / "Controllerfile").read_text(encoding="utf-8")
    image = f"docker.io/jenkins/jenkins@{EXPECTED['controller']['amd64_digest']}"
    require(image in content, "Controllerfile is not pinned to the controller digest")
    require(
        "--plugin-file /usr/share/jenkins/ref/plugins.lock.txt" in content,
        "Controllerfile must give the plugin manager a supported lock filename",
    )
    require("--latest=false" in content, "Controllerfile must install the exact plugin lock")
    require("sha256sum --check" in content, "Controllerfile must verify plugin artifacts")
    require("0.0.0.0" not in content and "--httpListenAddress" not in content, "Controllerfile declares a wildcard/public binding")
    require("50000" not in content, "Controllerfile exposes the inbound TCP agent port")


def check_casc(root: Path) -> None:
    content = (root / "casc" / "jenkins.yaml").read_text(encoding="utf-8")
    require(re.search(r"(?m)^  numExecutors: 0$", content) is not None, "JCasC must set zero executors")
    require(re.search(r"(?m)^  slaveAgentPort: -1$", content) is not None, "JCasC must disable the inbound TCP agent port")
    require('id: "jlab-admin"' in content, "JCasC must declare the fixed local administrator")
    require("allowsSignup: false" in content, "JCasC must disable signup")
    require("allowAnonymousRead: false" in content, "JCasC must disable anonymous access")
    require(
        "${trim:${readFile:/run/secrets/jlab-admin-password}}" in content,
        "JCasC password must be trimmed from a mounted file",
    )
    require('url: "http://127.0.0.1:18080/"' in content, "JCasC location must be loopback-only")
    require("0.0.0.0" not in content, "JCasC contains a wildcard address")


def check_repository_state(root: Path) -> None:
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        require(path.name not in RUNTIME_NAMES, f"runtime or credential state is committed: {path.relative_to(root)}")
        require(path.suffix.casefold() not in {".key", ".pem", ".log"}, f"unsafe file type is committed: {path.relative_to(root)}")


def run_check(root: Path) -> None:
    versions = json.loads((root / "config" / "versions.json").read_text(encoding="utf-8"))
    require(versions == EXPECTED, "config/versions.json does not match the program contract")
    check_controllerfile(root)
    check_casc(root)
    check_plugins(root)
    check_repository_state(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jlab")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("check", help="validate static controller configuration")
    args = parser.parse_args(argv)

    try:
        if args.command == "check":
            run_check(repository_root())
            print("static controller checks passed")
            return 0
    except (CheckFailure, OSError, json.JSONDecodeError) as error:
        print(f"jlab: configuration check failed: {error}", file=sys.stderr)
        return EXIT_CONFIGURATION
    return EXIT_CONFIGURATION


if __name__ == "__main__":
    raise SystemExit(main())
