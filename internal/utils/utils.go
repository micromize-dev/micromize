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

package utils

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

const (
	defaultLSMFilePath = "/sys/kernel/security/lsm"
	bpfLSMInstructions = `
To enable BPF LSM:
1. Ensure your kernel is compiled with CONFIG_BPF_LSM=y
2. Add 'lsm=<existing_lsms>,bpf' to your kernel boot parameters
   Example: lsm=lockdown,capability,yama,bpf
3. Reboot your system

For more information, see: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/`
)

var (
	// lsmFilePath is the path to the LSM file, exposed as a variable for testing
	lsmFilePath = defaultLSMFilePath
)

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func GetHostPidNamespaceID() (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat("/proc/1/ns/pid", &stat); err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

// ValidateBPFLSM checks if BPF LSM is enabled on the host system.
// It reads /sys/kernel/security/lsm and verifies that "bpf" is in the active LSM list.
// Returns an error with actionable information if BPF LSM is not enabled.
func ValidateBPFLSM() error {
	data, err := os.ReadFile(lsmFilePath)
	if err != nil {
		return fmt.Errorf("failed to read %s: Unable to verify whether BPF LSM is enabled: %w", lsmFilePath, err)
	}

	lsmList := strings.TrimSpace(string(data))
	if lsmList == "" {
		return fmt.Errorf("BPF LSM is not enabled on this host.\n"+
			"Detected LSMs: (none)\n"+
			"Required: bpf%s", bpfLSMInstructions)
	}

	lsms := strings.Split(lsmList, ",")

	for _, lsm := range lsms {
		if strings.TrimSpace(lsm) == "bpf" {
			return nil
		}
	}

	return fmt.Errorf("BPF LSM is not enabled on this host.\n"+
		"Detected LSMs: %s\n"+
		"Required: bpf%s", lsmList, bpfLSMInstructions)
}
