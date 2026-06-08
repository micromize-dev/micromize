# Development Setup

This guide covers the local environment needed to build, test, and run Micromize during development.

## Prerequisites

- Go `1.25.7`, as declared in `go.mod`
- Linux kernel `5.18+`; kernel `6.11+` is a good development baseline for current BPF LSM testing
- BPF LSM enabled (`CONFIG_BPF_LSM=y`) and included in the active LSM list
- IMA enabled (`CONFIG_IMA=y`) for execution integrity support through `bpf_ima_file_hash`
- `clang` and LLVM tooling for BPF compilation
- Docker for container-based testing
- `ig` CLI `v0.49+` for building and running gadgets

## Kernel Setup

Check whether BPF LSM is active:

```bash
cat /sys/kernel/security/lsm
```

The output should include `bpf`. If it does not, confirm the kernel was built with BPF LSM support:

```bash
zgrep CONFIG_BPF_LSM /proc/config.gz
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```

If `CONFIG_BPF_LSM=y` is present but `bpf` is not in `/sys/kernel/security/lsm`, add `bpf` to the kernel boot
parameter, for example:

```text
lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

Reboot after changing the boot parameter and re-check `/sys/kernel/security/lsm`.

For development from macOS or another non-Linux host, use a Linux VM with BPF LSM support. Lima, Vagrant, or a cloud VM are
all reasonable options as long as the kernel exposes BPF LSM, IMA, `/sys/fs/bpf`, and Docker.

## Install `ig`

Install the Inspektor Gadget CLI from the upstream quickstart:

```bash
curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.49.1/ig-linux-amd64-v0.49.1.tar.gz \
  | sudo tar -C /usr/local/bin -xzf - ig
```

Verify the install:

```bash
ig version
```

## Build

Build the gadgets first, then the application binary:

```bash
make build-gadgets
make build-app
```

Or run both steps together:

```bash
make build-all
```

Gadget builds call `ig image build` and `ig image export`, so they require `sudo` and a Linux system with the BPF-related
kernel features above. The built gadget archives are written to `build/gadgets/`, and application binaries are written to
`dist/`.

## Run Locally

Micromize needs elevated privileges because BPF programs require kernel capabilities such as `CAP_SYS_ADMIN` on many
development systems.

Run a gadget directly in audit mode:

```bash
sudo -E ig run ghcr.io/micromize-dev/micromize/cap-restrict:latest --enforce=false
```

Run in enforce mode:

```bash
sudo -E ig run ghcr.io/micromize-dev/micromize/cap-restrict:latest --enforce=true
```

You can also use the Makefile targets:

```bash
make run-cap-restrict PARAMS="--enforce=false"
make run-fs-restrict PARAMS="--enforce=false"
make run-socket-restrict PARAMS="--enforce=false"
```

## Test with Docker

In one terminal, run Micromize in audit mode. In another terminal, start a simple container:

```bash
docker run --rm -it alpine sh
```

Try actions related to the gadget under test, then inspect Micromize logs. Start with audit mode while developing a policy
so unexpected behavior is logged instead of blocked.

## Validation

Run Go tests:

```bash
make test
```

Run lint through the project linter container:

```bash
make lint
```

Check license headers for Go files:

```bash
make license-check
```

Install commit-message hooks if you want local validation before pushing:

```bash
make setup-hooks
```

## Troubleshooting

### `bpf` is missing from `/sys/kernel/security/lsm`

Confirm `CONFIG_BPF_LSM=y`, add `bpf` to the `lsm=` boot parameter, reboot, and check again.

### Gadget build fails because `ig` is missing

Install `ig` and make sure it is on `PATH`:

```bash
command -v ig
ig version
```

### Permission errors while building or running gadgets

Run the gadget build or `ig run` command with `sudo -E`. BPF loading and LSM attachment need elevated kernel privileges on
development machines.

### Docker test containers are not visible

Confirm Docker is running and that Micromize can access the host namespaces and BPF filesystem. For containerized
Micromize runs, mount `/sys/fs/bpf`, `/sys/kernel/debug`, `/sys/kernel/security`, `/proc`, and runtime directories as shown
in the README Docker quickstart.

### IMA hash features do not work

Confirm the kernel has IMA enabled:

```bash
zgrep CONFIG_IMA /proc/config.gz
grep CONFIG_IMA /boot/config-$(uname -r)
```
