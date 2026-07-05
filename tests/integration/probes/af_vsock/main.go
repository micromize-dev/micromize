// Copyright The micromize authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	afVSOCK       = 40
	sockStream    = 1
	sockSeqpacket = 5
)

// AF_VSOCK probe. Exits 0 in both audit and enforce modes so the harness can
// drive the audit-vs-enforce distinction externally (by toggling micromize's
// --enforce flag) while still asserting on the probe's printed status.
//
//	"ok: AF_VSOCK socket created (audit-mode or opt-out)"   socket() returned an fd
//	"blocked: AF_VSOCK socket creation denied: <errno>"     socket() returned EPERM/EACCES
//	"skipped: AF_VSOCK not supported on this kernel"        socket() returned EAFNOSUPPORT/EPROTONOSUPPORT
//
// Exit codes:
//
//	0  ok / blocked / skipped (any expected outcome)
//	2  unexpected error
func main() {
	fd, err := syscall.Socket(afVSOCK, sockStream, 0)
	if err == nil {
		syscall.Close(fd) //nolint:errcheck,gosec
		fmt.Println("ok: AF_VSOCK socket created (audit-mode or opt-out)")
		return
	}

	switch err {
	case syscall.EPERM, syscall.EACCES:
		fmt.Printf("blocked: AF_VSOCK socket creation denied: %v\n", err)
		return
	case syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT:
		fmt.Printf("skipped: AF_VSOCK not supported on this kernel: %v\n", err)
		return
	}

	// SOCK_STREAM is the newer transport; some older kernels only support
	// SOCK_SEQPACKET. Retry once before declaring the result unexpected.
	fd, err = syscall.Socket(afVSOCK, sockSeqpacket, 0)
	if err == nil {
		syscall.Close(fd) //nolint:errcheck,gosec
		fmt.Println("ok: AF_VSOCK socket created (audit-mode or opt-out)")
		return
	}
	switch err {
	case syscall.EPERM, syscall.EACCES:
		fmt.Printf("blocked: AF_VSOCK socket creation denied: %v\n", err)
		return
	case syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT:
		fmt.Printf("skipped: AF_VSOCK not supported on this kernel: %v\n", err)
		return
	}

	fmt.Printf("socket-error: %v\n", err)
	os.Exit(2)
}
