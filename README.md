# jenkins-controller

This repository builds a disposable, local-only Jenkins controller for the
Podman Tools public verification lab. The controller is an orchestrator: it
has zero executors, exposes no inbound TCP agent port, and accepts disposable
agents through WebSocket Remoting in later migration slices.

The current slice supplies the immutable static definition and portable
validation. It does not start Podman or create runtime state.

Loopback-only publication prevents access through non-loopback host
interfaces; it is not a sandbox from other host processes or containers that
share the host network namespace. A host-networked development container can
reach `127.0.0.1:18080`. Later disposable Jenkins agents instead use the
private lab bridge and receive neither developer credential mounts nor an
engine socket.

## Program versions

- Jenkins controller: `2.568.1-jdk21`
- AMD64 controller digest:
  `sha256:8279be0a0ed95ad3b67c8677b9e03ff322f61338d39244234a907e9039ac3683`
- Jenkins Remoting: `3384.v60d89463d9e0`
- Remoting SHA-256:
  `2eba7803ff8f59d25b6cac7c13f4f99d39ed6173bf011f8b781b35d0a5e76f19`

The machine-readable authority is [`config/versions.json`](config/versions.json).
The local controller image name is
`localhost/jenkins-controller:lab-local`.

## Static validation

Requirements are Bash and Python 3.11 or newer:

```bash
./scripts/jlab check
python3 -m unittest discover
bash -n scripts/jlab scripts/check-publication scripts/refresh-plugins
shellcheck scripts/jlab scripts/check-publication scripts/refresh-plugins
PUBLICATION_DENYLIST="$HOME/.config/thelarklan/publication-denylist.txt" \
  ./scripts/check-publication
git diff --check
```

`jlab check` validates the version contract, the digest-pinned Controllerfile,
the complete plugin lock and checksum coverage, the zero-executor local realm,
disabled inbound TCP port, loopback-only declared location, and absence of
committed runtime or credential state. It does not contact the network or run
Podman.

## Plugin lock

`plugins.requested.txt` is the small human-reviewed request set.
`plugins.lock` is the complete versioned dependency closure produced by the
official `jenkins-plugin-cli` in the pinned controller image.
`plugins.sha256` records every downloaded `.jpi` artifact.

Refreshing is an explicit, network-enabled upgrade operation:

```bash
./scripts/refresh-plugins
git diff -- plugins.lock plugins.sha256
./scripts/jlab check
```

The refresh uses the digest-pinned controller image, resolves the latest
compatible transitive dependencies for the fixed Jenkins version, downloads
all artifacts into a temporary directory, and regenerates the two files. A
non-upgrade refresh must be byte-identical. Review any change and all reported
plugin security warnings before accepting it.

## Deferred runtime

Later slices implement deterministic image materialization, loopback-only host
publication, owner-only bootstrap secrets, disposable WebSocket agents, safe
lifecycle operations, and snapshot smoke builds. No production deployment,
registry publishing, webhooks, persistent service, or backup behavior belongs
to this repository.
