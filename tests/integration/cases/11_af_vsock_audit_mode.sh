#!/usr/bin/env bash
# Test: AF_VSOCK socket-restrict in audit mode
#
# AF_VSOCK is intentionally NOT in the default socket-restrict deny-list — it
# can be used by firecracker / kata-containers / hypervisor agents. This test
# opts in AF_VSOCK via --socket-deny-families and runs micromize in audit
# mode (--enforce=false), so the socket call is *allowed* but the gadget
# emits an event. The probe asserts the socket() was not blocked; the harness
# is expected to additionally verify a "Socket family denied (create)" event
# was logged by micromize (this is harness-side and not part of the probe).
#
# Expected harness configuration:
#   MICROMIZE_SOCKET_DENY_FAMILIES=AF_VSOCK
#   MICROMIZE_ENFORCE=false
# These are read by the harness when launching micromize before this case
# executes, mirroring the convention used by the existing AF_ALG cases (which
# rely on the harness to have micromize already running in enforce mode).

test_af_vsock_audit_mode() {
  begin_test "AF_VSOCK socket allowed in audit mode while opted into deny-list"

  if ! command -v go &>/dev/null; then
    fail_test "go is required to build the AF_VSOCK probe"
    return
  fi

  local probe_bin="${ROOTFS_DIR}/bin/af-vsock-probe"
  if ! (cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$probe_bin" ./tests/integration/probes/af_vsock); then
    fail_test "failed to build AF_VSOCK probe"
    return
  fi

  local bundle="${TEST_TMPDIR}/bundle-af-vsock"
  local cid="micromize-test-af-vsock"

  create_bundle "$bundle" "$ROOTFS_DIR" /bin/af-vsock-probe

  local output
  output=$(runc run "$cid" -b "$bundle" 2>&1)
  local rc=$?

  if [[ $rc -ne 0 ]]; then
    fail_test "AF_VSOCK probe exited with ${rc}: ${output}"
    runc delete -f "$cid" 2>/dev/null || true
    return
  fi

  # In audit mode the socket call must succeed (audit only emits an event).
  # Accept "skipped" for kernels without AF_VSOCK so the case is portable.
  if echo "$output" | grep -qE "^(ok|skipped):"; then
    pass_test
  else
    fail_test "Expected AF_VSOCK socket to be allowed in audit mode, got: ${output}"
  fi

  runc delete -f "$cid" 2>/dev/null || true
}

test_af_vsock_audit_mode
