<h1>
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/images/logo/logo-horizontal.svg">
    <img src="docs/images/logo/logo-horizontal.svg" alt="Micromize Logo" width="80%">
  </picture>
</h1>

Kernel-enforced boundary hardening for cloud-native containers.

Micromize uses [BPF-LSM](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/) to enforce what well-behaved cloud-native containers should look like. Micromize is built on [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget).

## The Problem

Containers rely on namespaces, cgroups, seccomp, and LSMs but they still expose kernel attack surface. Misconfigured or overly privileged workloads lead to container escape primitives, host mutation from containers, runtime drift from the image, and undefined kernel behavior.

Tools may detect this. Few eliminate it.

## Philosophy

Micromize doesn't care what happens inside the container. Instead, it enforces the boundaries. You can't effectively protect against every poorly written application, but you can guarantee a container stays within the limits of what a container is meant to be.

Micromize assumes containers are immutable, disposable, non-host-mutating, and explicit about privilege.

If your workload violates those assumptions, Micromize blocks it or forces an explicit posture decision.

> Want to go further and guarantee that only the exact, cryptographically signed binaries from your image can execute? See **[Sigward](#sigward)**, the execution-attestation product that ships from this repository.

## What Micromize Does

Today, Micromize attaches eBPF programs to LSM hooks and enforces:

- **Strict container boundaries** — blocks filesystem escapes and host access
- **Capability restriction** — prevents privilege escalation via `unshare`/`clone`/`setns`
- **Ptrace blocking** — eliminates ptrace-based debugging/injection attacks
- **Socket restriction** — blocks `AF_ALG` (kernel crypto userspace API) socket usage in containers, mitigating CVE-2026-31431 and related attack surface

Policies are loaded before container start and enforced at execution time. No runtime replacement. No learning mode. Kernel-native enforcement.

## Sigward

This repository is a monorepo that ships **two** products from a shared codebase:

- **Micromize** (`cmd/micromize`) — the boundary-enforcement agent described above.
- **[Sigward](gadgets/sigward)** (`cmd/sigward`) — execution attestation. Sigward verifies, in the kernel (BPF-LSM + IMA), that every binary and shared object a container runs matches a cryptographically signed SPDX SBOM attached to its image. Anything unattested or tampered with is blocked before it executes.

They are separate deployables — separate binaries, images, and Helm charts (`charts/sigward`) — so Sigward's registry access, credentials, and `CONFIG_IMA` requirement never get forced onto a plain Micromize deployment. Deploy either or both; they compose at the LSM layer.

## Quickstart

### Docker

```bash
docker run -it \
  --name micromize \
  --pid=host \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/security:/sys/kernel/security:ro \
  -v /bin:/host/bin \
  -v /proc:/host/proc \
  -v /run:/host/run \
  -v /usr:/host/usr \
  ghcr.io/micromize-dev/micromize:latest
```

### Kubernetes (Helm)

```bash
# Resolve the micromize image digest for self-exclusion filtering
DIGEST=$(crane digest ghcr.io/micromize-dev/micromize:<tag>)

helm install micromize ./charts/micromize \
  --namespace micromize \
  --create-namespace \
  --set image.tag=<tag> \
  --set image.digest=$DIGEST
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--enforce` | `true` | Enforce restrictions (block) vs audit mode |
| `--verbose` / `-v` | `false` | Debug logging |
| `--filter-namespaces` | `""` | Comma-separated K8s namespaces to monitor (`!` prefix to exclude). The `micromize` namespace is always excluded. |
| `--filter-image-digest` | `""` | Filter out containers running this image digest from monitoring |
| `--disable-gadgets` | `""` | Comma-separated list of gadgets to disable (e.g. `ptrace-restrict,cap-restrict`) |
| `--exempt-label` | `micromize.dev/exempt` | Kubernetes label key used to mark namespaces as exempt (value must be `true`). Evaluated at startup only. Set to `""` to disable. |

## Requirements

- Linux kernel 5.18+
- BPF LSM enabled (`CONFIG_BPF_LSM=y`, boot with `lsm=...,bpf`)

## Development

Requires [`ig`](https://inspektor-gadget.io/docs/latest/quick-start#linux) CLI v0.49+ for building gadgets.

```bash
# Build everything (gadgets + binary). Requires sudo.
make build-all

# Run tests
make test
```

For full development environment setup, kernel prerequisites, audit/enforce mode examples, and troubleshooting, see
[docs/development.md](docs/development.md).

## Status

Micromize is under active development. Contributions are welcome.
