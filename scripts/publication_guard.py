#!/usr/bin/env python3
"""Scan public text and reachable Git objects without revealing denylist terms."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


MIN_SUBSTRING = 20
TOKEN = re.compile(r"[a-z0-9][a-z0-9._@:/+-]{3,}", re.IGNORECASE)
URL = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
RUNTIME_PATH = re.compile(
    r"(?:^|/)(?:hosts\.yml|credentials\.xml|state\.json|secrets?\.json)$",
    re.IGNORECASE,
)
RULES = (
    ("private key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "credential assignment",
        re.compile(
            r"(?im)^\s*(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
            r"\s*[:=]\s*(?![\"']?\$\{)[^\s#]{8,}\s*$"
        ),
    ),
    (
        "private host path",
        re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/(?:projects|Documents|Desktop)/"),
    ),
)


def sha(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("utf-8")).hexdigest()


def terms(text: str) -> set[str]:
    normalized = text.strip().casefold()
    if not normalized or normalized.startswith("#"):
        return set()
    base = {normalized}
    base.update(match.group(0).strip("./:@+-") for match in TOKEN.finditer(normalized))
    for match in URL.finditer(normalized):
        parsed = urlsplit(match.group(0))
        base.update(filter(None, (parsed.hostname, unquote(parsed.path))))
        base.update(part for part in unquote(parsed.path).split("/") if part)
    expanded: set[str] = set()
    for item in base:
        if not item:
            continue
        expanded.add(item)
        if len(item) < MIN_SUBSTRING:
            continue
        for width in range(MIN_SUBSTRING, min(len(item), 64) + 1):
            for start in range(len(item) - width + 1):
                expanded.add(item[start : start + width])
    return expanded


def denylist_hashes(path: Path) -> set[str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError("denylist must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("denylist mode must be 0600")
    values: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        values.update(sha(item) for item in terms(line))
    return values


def hash_file(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    values: set[str] = set()
    for line in path.read_text(encoding="ascii").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"invalid SHA-256 line in {path}")
        values.add(value)
    return values


def findings(label: str, text: str, forbidden: set[str]) -> list[str]:
    result = [f"{label}: {name}" for name, pattern in RULES if pattern.search(text)]
    for match in URL.finditer(text):
        parsed = urlsplit(match.group(0))
        if parsed.scheme.casefold() != "https" and parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "controller",
        }:
            result.append(f"{label}: unsafe cleartext URL")
            break
    if forbidden and any(sha(item) in forbidden for item in terms(text)):
        result.append(f"{label}: private denylist hash match")
    return result


def scan_files(paths: list[Path], forbidden: set[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        if RUNTIME_PATH.search(path.as_posix()):
            result.append(f"{path}: runtime credential state")
        data = path.read_bytes()
        if b"\x00" not in data:
            result.extend(findings(str(path), data.decode("utf-8", errors="replace"), forbidden))
    return result


def git(repository: Path, *arguments: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )


def scan_git(repository: Path, forbidden: set[str]) -> list[str]:
    result: list[str] = []
    for line in git(repository, "rev-list", "--objects", "--all").stdout.splitlines():
        object_id, _, object_path = line.partition(" ")
        object_type = git(repository, "cat-file", "-t", object_id).stdout.strip()
        if object_path:
            result.extend(findings(f"git-object-path:{object_id}", object_path, forbidden))
        if object_type not in {"blob", "commit", "tag"}:
            continue
        data = git(repository, "cat-file", object_type, object_id, text=False).stdout
        if b"\x00" not in data:
            result.extend(
                findings(
                    f"git-object:{object_id}",
                    data.decode("utf-8", errors="replace"),
                    forbidden,
                )
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--denylist", type=Path)
    parser.add_argument("--hash-file", type=Path)
    parser.add_argument("--write-hashes", type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    try:
        forbidden = hash_file(args.hash_file)
        if args.denylist:
            private_hashes = denylist_hashes(args.denylist)
            forbidden.update(private_hashes)
            if args.write_hashes:
                args.write_hashes.write_text("".join(f"{item}\n" for item in sorted(private_hashes)), encoding="ascii")
        result = scan_files([Path(path) for path in args.paths], forbidden)
        if args.repository:
            result.extend(scan_git(args.repository.resolve(), forbidden))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"publication guard: {error}", file=sys.stderr)
        return 2
    for item in result:
        print(item, file=sys.stderr)
    return 1 if result else 0


if __name__ == "__main__":
    raise SystemExit(main())
