#!/usr/bin/env python3
"""Generate deterministic Jenkins plugin locks from downloaded artifacts."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import zipfile
from pathlib import Path


class LockError(Exception):
    pass


def parse_manifest(data: bytes) -> dict[str, str]:
    unfolded: list[str] = []
    for line in data.decode("utf-8", errors="strict").splitlines():
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    values: dict[str, str] = {}
    for line in unfolded:
        key, separator, value = line.partition(": ")
        if separator:
            values[key] = value
    return values


def plugin_metadata(path: Path) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(path) as archive:
            manifest = parse_manifest(archive.read("META-INF/MANIFEST.MF"))
    except (OSError, KeyError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        raise LockError(f"cannot read plugin artifact {path.name}: {error}") from error
    name = manifest.get("Short-Name", path.stem)
    version = manifest.get("Plugin-Version") or manifest.get("Implementation-Version")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) or not version:
        raise LockError(f"invalid plugin metadata in {path.name}")
    if name != path.stem:
        raise LockError(f"artifact name {path.name} does not match Short-Name {name}")
    return name, version


def artifacts(directory: Path) -> list[tuple[str, str, str]]:
    values: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.jpi")):
        name, version = plugin_metadata(path)
        if name in seen:
            raise LockError(f"duplicate plugin artifact: {name}")
        seen.add(name)
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        values.append((name, version, checksum))
    if not values:
        raise LockError("plugin directory contains no .jpi artifacts")
    return values


def generate(directory: Path, lock_path: Path, checksum_path: Path) -> None:
    values = artifacts(directory)
    lock_path.write_text(
        "".join(f"{name}:{version}\n" for name, version, _ in values),
        encoding="utf-8",
    )
    checksum_path.write_text(
        "".join(f"{checksum}  {name}.jpi\n" for name, _, checksum in values),
        encoding="ascii",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin-dir", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    args = parser.parse_args()
    try:
        generate(args.plugin_dir, args.lock, args.checksums)
    except LockError as error:
        print(f"plugin lock: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
