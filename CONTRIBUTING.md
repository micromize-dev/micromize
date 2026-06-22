# Contributing to Micromize

Thank you for your interest in contributing to Micromize! This document provides everything you need to know to contribute effectively.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Environment Setup](#development-environment-setup)
- [Building the Project](#building-the-project)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Commit Message Convention](#commit-message-convention)
- [Reporting Issues](#reporting-issues)

## Prerequisites

Before you begin, ensure you have the following installed:

- **Go 1.25+** — [Installation guide](https://go.dev/doc/install)
- **Docker** — Required for building Docker images and running the linter
- **Linux kernel 5.18+** — Required for BPF/LSM features (development and runtime)
- **BPF LSM enabled** — Boot with `lsm=...,bpf` and ensure `CONFIG_BPF_LSM=y`
- **IMA enabled** — `CONFIG_IMA=y` required for execution integrity checks
- **Inspektor Gadget CLI (`ig`) v0.49+** — Required for building gadgets: [Quick start](https://inspektor-gadget.io/docs/latest/quick-start#linux)
- **clang-format** — Used for BPF C code formatting
- **Helm** — Required for Kubernetes deployment

### Optional

- **kubectl** — For Kubernetes deployment and debugging
- **crane** — For resolving container image digests

## Development Environment Setup

1. **Fork and clone the repository:**

   ```bash
   git clone https://github.com/<your-username>/micromize.git
   cd micromize
   ```

2. **Install git hooks** (required for commit message validation):

   ```bash
   make setup-hooks
   ```

   This installs the `conform` tool and configures git to use the commit-msg hook. Without this, commits will be rejected by CI.

3. **Verify your setup:**

   ```bash
   # Check Go version
   go version  # Should be 1.25+

   # Check Docker
   docker --version

   # Check ig CLI
   ig version  # Should be 0.49+

   # Run tests
   make test
   ```

## Building the Project

### Quick Build

```bash
# Build everything (gadgets + binary). Requires sudo for gadget builds.
sudo make build-all
```

This builds all BPF gadgets and the main application binary.

### Incremental Builds

```bash
# Build a specific gadget (e.g., cap-restrict)
make cap-restrict

# Build only the application (no gadgets)
make build-app

# Build gadgets only
make build-gadgets
```

### Cross-Compilation

The project supports building for both `amd64` and `arm64`:

```bash
# Builds produce output in the dist/ directory
make build-all
ls dist/  # micromize-linux-amd64, micromize-linux-arm64
```

### Docker Image

```bash
# Build the Docker image
docker build -t micromize:dev .
```

### Clean

```bash
make clean  # Removes dist/, build/src/, build/gadgets/
```

## Running Tests

```bash
# Run all Go tests
make test

# Or directly
go test ./...
```

Tests run as part of CI on every push and pull request.

## Code Style

### Go Code

- Follow standard Go formatting (`gofmt` / `go fmt`)
- Run the linter: `make lint` (uses `golangci-lint` in Docker)
- License headers are checked automatically: `make license-check`

### BPF C Code

BPF programs live in `gadgets/*/program.bpf.c` and `gadgets/*/*.bpf.h`. Format them with:

```bash
make clang-format
```

This runs `clang-format -i` on all `.bpf.c` and `.bpf.h` files.

### Git Hooks

After running `make setup-hooks`, every commit is validated by [conform](https://sider.github.io/). Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) format (see below).

## Submitting a Pull Request

1. **Create a feature branch** from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit them following the [commit convention](#commit-message-convention).

3. **Push to your fork:**

   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a Pull Request:**

   - Use the PR template (provided automatically by GitHub)
   - Link any related issues (e.g., "Closes #41")
   - Describe the changes in detail
   - Include screenshots or logs if relevant

5. **Address review feedback** — Maintainers will review your PR. Make requested changes and push additional commits.

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] Code follows the project's style guidelines
- [ ] Commit messages follow Conventional Commits
- [ ] New code is covered by tests where applicable
- [ ] Documentation is updated if needed

## Commit Message Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/) enforced by the `conform` git hook.

### Allowed Types

| Type     | Description                                      |
| -------- | ------------------------------------------------ |
| `feat`   | A new feature                                    |
| `fix`    | A bug fix                                        |
| `docs`   | Documentation only changes                       |
| `style`  | Code style (formatting, semicolons, etc.)        |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf`   | Performance improvement                          |
| `test`   | Adding or updating tests                         |
| `build`  | Changes to build system or dependencies          |
| `ci`     | Changes to CI configuration                      |
| `chore`  | Other changes that don't modify src or test files |
| `revert` | Reverts a previous commit                        |

### Format

```
<type>(<scope>): <description>

[optional body]
```

### Examples

```
feat(gadgets): add socket-restrict gadget
fix(runtime): handle nil namespace in filter
docs: update README quickstart section
style(gadgets): format BPF code with clang-format
test: add unit test for capability checker
```

### Scopes

Common scopes: `gadgets`, `runtime`, `operators`, `logger`, `utils`, `helm`, `ci`, `deps`, `*` (any).

## Reporting Issues

Before opening an issue:

1. **Search existing issues** — Make sure the issue hasn't already been reported.
2. **Check requirements** — Ensure your environment meets the [prerequisites](#prerequisites).

When filing a bug report, please include:

- Steps to reproduce
- Expected vs. actual behavior
- Environment details (OS, kernel version, Go version)
- Relevant logs or error messages

For feature requests, describe:

- The problem you're trying to solve
- Why it aligns with Micromize's philosophy (kernel-native enforcement, not scanning)

## Project Structure

```
micromize/
├── cmd/                  # Main application entry point
├── internal/             # Internal Go packages
├── gadgets/              # BPF gadget definitions (program.bpf.c + manifest)
├── charts/               # Helm chart for Kubernetes deployment
├── docs/                 # Documentation and images
├── include/gadget/       # Inspektor Gadget headers (generated)
├── tests/                # Integration tests
├── Makefile              # Build automation
├── Dockerfile            # Container build
└── go.mod                # Go module dependencies
```

## Philosophy

Remember Micromize's core philosophy: **enforce boundaries, don't scan internals**. When contributing, consider whether your change aligns with this principle. Micromize assumes containers are immutable, disposable, non-host-mutating, and explicit about privilege.

## Getting Help

- Open a [GitHub Discussion](https://github.com/micromize-dev/micromize/discussions) for questions
- Check the [README](README.md) for quickstart and usage
- Look at existing issues labeled `good first issue` for beginner-friendly tasks

Thank you for contributing!
