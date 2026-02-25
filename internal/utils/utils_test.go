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
	"os"
	"path/filepath"
	"testing"
)

func TestValidateBPFLSM(t *testing.T) {
	tests := []struct {
		name        string
		lsmContent  string
		shouldError bool
	}{
		{
			name:        "BPF LSM enabled",
			lsmContent:  "lockdown,capability,yama,bpf",
			shouldError: false,
		},
		{
			name:        "BPF LSM enabled with spaces",
			lsmContent:  "lockdown, capability, yama, bpf",
			shouldError: false,
		},
		{
			name:        "BPF LSM enabled first",
			lsmContent:  "bpf,capability,yama",
			shouldError: false,
		},
		{
			name:        "BPF LSM enabled only",
			lsmContent:  "bpf",
			shouldError: false,
		},
		{
			name:        "BPF LSM not enabled",
			lsmContent:  "lockdown,capability,yama",
			shouldError: true,
		},
		{
			name:        "empty LSM list",
			lsmContent:  "",
			shouldError: true,
		},
		{
			name:        "BPF LSM with newline",
			lsmContent:  "lockdown,capability,bpf\n",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file to simulate /sys/kernel/security/lsm
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "lsm")

			if err := os.WriteFile(tmpFile, []byte(tt.lsmContent), 0600); err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}

			// Temporarily replace the lsmFilePath for testing
			originalPath := lsmFilePath
			lsmFilePath = tmpFile
			defer func() { lsmFilePath = originalPath }()

			err := ValidateBPFLSM()

			if tt.shouldError && err == nil {
				t.Errorf("Expected error, but got nil")
			}

			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			}
		})
	}
}

func TestValidateBPFLSM_FileNotFound(t *testing.T) {
	// Test when the LSM file doesn't exist
	originalPath := lsmFilePath
	lsmFilePath = "/nonexistent/path/lsm"
	defer func() { lsmFilePath = originalPath }()

	err := ValidateBPFLSM()
	if err == nil {
		t.Errorf("Expected error when file doesn't exist, but got nil")
	}
}
