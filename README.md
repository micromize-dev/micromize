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

Micromize doesn't care what happens inside the container. Instead, it enforces the boundaries. We don't scan for cryptominers because with Micromize, unauthorized binaries can't execute in the first place. You can't effectively protect against every poorly written application, but you can guarantee that nothing runs unless it was part of the original image.

Micromize assumes containers are immutable, disposable, non-host-mutating, and explicit about privilege.

If your workload violates those assumptions, Micromize blocks it or forces an explicit posture decision.

## What Micromize Does

Today, Micromize attaches eBPF programs to LSM hooks and enforces:

- **Strict container boundaries** — blocks filesystem escapes and host access
- **Capability restriction** — prevents privilege escalation via `unshare`/`clone`/`setns`
- **Ptrace blocking** — eliminates ptrace-based debugging/injection attacks
- **Socket restriction** — blocks `AF_ALG` (kernel crypto userspace API) socket usage in containers, mitigating CVE-2026-31431 and related attack surface
- **Execution integrity** — SBOM + runtime hash validation via `bpf_ima_file_hash`

Policies are loaded before container start and enforced at execution time. No runtime replacement. No learning mode. Kernel-native enforcement.

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
- IMA enabled (`CONFIG_IMA=y`) — required for execution integrity via `bpf_ima_file_hash`

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
