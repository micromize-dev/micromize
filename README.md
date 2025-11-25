<h1>
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/images/logo/logo-horizontal.svg">
    <img src="docs/images/logo/logo-horizontal.svg" alt="Micromize Logo" width="80%">
  </picture>
</h1>

**Micromize** is a security hardening tool designed to reduce the visible kernel surface for containerized applications by leveraging [BPF LSM](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/).

This project is currently experimental. Features and APIs are subject to change. Use with caution in production environments.

## Overview

The core philosophy of Micromize is simple: **Instant hardening by default.**

Traditional container security often involves creating complex profiles (like Seccomp or SELinux) for each application to restrict its capabilities. Micromize flips this model. Instead of defining what each container *can* do, Micromize applies a broad set of sensible restrictions to *all* containers running on a node, blocking dangerous kernel control flows that are rarely needed by legitimate containerized workloads and often used for container escapes.

By deploying Micromize to your nodes, you instantly harden the entire node. You then manage **exclusions** for specific workloads that require broader permissions, rather than managing restriction profiles for everyone else.

## Available Gadgets

Micromize is built on [Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget) and employs the "gadget mindset", creating a modular architecture to load and execute eBPF programs. It currently provides the following gadgets to enforce restrictions:

- **`fs-restrict`**: Restricts access to sensitive parts of the filesystem.
- **`kmod-restrict`**: Prevents containers from loading kernel modules.

### Prerequisites

- Linux kernel with BPF LSM support (5.7+ recommended).
- `ig` CLI tool installed.

### Building

```bash
make build-all
```

### Running

```bash
sudo dist/micromize-linux-[amd64|arm64]
```

