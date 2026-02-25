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

package sbom

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4/testutils/require"
)

func TestNormalizeImageRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"empty", "", ""},
		{"bare image", "nginx", "docker.io/library/nginx"},
		{"bare with tag", "nginx:latest", "docker.io/library/nginx:latest"},
		{"user image", "moby/buildkit", "docker.io/moby/buildkit"},
		{"user with tag", "moby/buildkit:v0.12", "docker.io/moby/buildkit:v0.12"},
		{"ghcr", "ghcr.io/org/image:v1", "ghcr.io/org/image:v1"},
		{"ecr", "123456.dkr.ecr.us-east-1.amazonaws.com/repo:tag", "123456.dkr.ecr.us-east-1.amazonaws.com/repo:tag"},
		{"localhost", "localhost/myimage:dev", "localhost/myimage:dev"},
		{"localhost port", "localhost:5000/myimage", "localhost:5000/myimage"},
		{"registry port", "registry.example.com:5000/img", "registry.example.com:5000/img"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeImageRef(tt.ref); got != tt.want {
				t.Errorf("NormalizeImageRef(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestImageRefFromOCIConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		want      string
		wantError bool
	}{
		{"empty", "", "", false},
		{"invalid json", "not-json", "", true},
		{"no annotations", `{"annotations":{}}`, "", false},
		{"kubernetes cri", `{"annotations":{"io.kubernetes.cri.image-name":"docker.io/library/nginx:latest"}}`, "docker.io/library/nginx:latest", false},
		{"cri-o", `{"annotations":{"io.kubernetes.cri-o.ImageName":"quay.io/app:v1"}}`, "quay.io/app:v1", false},
		{"containerd", `{"annotations":{"io.containerd.image.name":"ghcr.io/org/img:sha-abc"}}`, "ghcr.io/org/img:sha-abc", false},
		{"priority cri over containerd", `{"annotations":{"io.kubernetes.cri.image-name":"first","io.containerd.image.name":"second"}}`, "first", false},
		{"empty value skipped", `{"annotations":{"io.kubernetes.cri.image-name":"","io.containerd.image.name":"fallback"}}`, "fallback", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ImageRefFromOCIConfig(tt.config)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchForImage_EmptyRef(t *testing.T) {
	f := NewFetcher()
	data, err := f.FetchForImage(t.Context(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil for empty ref, got %d bytes", len(data))
	}
}

func TestImageRefFromDockerConfig(t *testing.T) {
	// Create a fake Docker data root with a container config.
	tmpDir := t.TempDir()
	containerID := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	containerDir := filepath.Join(tmpDir, "containers", containerID)
	if err := os.MkdirAll(containerDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeConfig := func(image string) {
		cfg := map[string]any{"Config": map[string]string{"Image": image}}
		data, err := json.Marshal(cfg)
		require.NoError(t, err)
		if err := os.WriteFile(filepath.Join(containerDir, "config.v2.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Temporarily override dockerDataRoots to use our tmpDir.
	origFn := dockerDataRootsFn
	dockerDataRootsFn = func() []string { return []string{tmpDir} }
	t.Cleanup(func() { dockerDataRootsFn = origFn })

	t.Run("valid config", func(t *testing.T) {
		writeConfig("nginx:latest")
		got := ImageRefFromDockerConfig(containerID)
		if got != "nginx:latest" {
			t.Errorf("got %q, want %q", got, "nginx:latest")
		}
	})

	t.Run("empty image", func(t *testing.T) {
		writeConfig("")
		got := ImageRefFromDockerConfig(containerID)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("invalid container ID", func(t *testing.T) {
		got := ImageRefFromDockerConfig("../../../etc/passwd")
		if got != "" {
			t.Errorf("got %q, want empty for invalid ID", got)
		}
	})

	t.Run("empty container ID", func(t *testing.T) {
		got := ImageRefFromDockerConfig("")
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("nonexistent container", func(t *testing.T) {
		got := ImageRefFromDockerConfig("aabbccddee112233445566778899001122334455667788990011223344556677")
		if got != "" {
			t.Errorf("got %q, want empty for nonexistent container", got)
		}
	})
}

func TestExtractSPDXFromDSSE(t *testing.T) {
	makeDSSE := func(predicateType string, predicate any) []byte {
		statement := map[string]any{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"predicateType": predicateType,
			"predicate":     predicate,
		}
		statementBytes, _ := json.Marshal(statement)
		envelope := map[string]string{
			"payload": base64.StdEncoding.EncodeToString(statementBytes),
		}
		b, _ := json.Marshal(envelope)
		return b
	}

	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		wantNil   bool
		checkJSON string // expected JSON substring in result
	}{
		{
			name:    "valid SPDX envelope",
			input:   makeDSSE(spdxPredicateType, map[string]string{"spdxVersion": "SPDX-2.3"}),
			wantErr: false,
			wantNil: false,
		},
		{
			name:    "wrong predicate type",
			input:   makeDSSE("https://slsa.dev/provenance/v0.2", map[string]string{}),
			wantErr: true,
		},
		{
			name:    "invalid JSON envelope",
			input:   []byte("not-json"),
			wantErr: true,
		},
		{
			name: "invalid base64 payload",
			input: func() []byte {
				b, _ := json.Marshal(map[string]string{"payload": "!!invalid-base64!!"})
				return b
			}(),
			wantErr: true,
		},
		{
			name: "invalid JSON in payload",
			input: func() []byte {
				b, _ := json.Marshal(map[string]string{
					"payload": base64.StdEncoding.EncodeToString([]byte("not-json")),
				})
				return b
			}(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractSPDXFromDSSE(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %d bytes", len(got))
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			// Verify it's valid JSON
			if !json.Valid(got) {
				t.Errorf("result is not valid JSON: %s", got)
			}
		})
	}
}

func TestParseFiles_RejectsRelativePaths(t *testing.T) {
	makeSBOM := func(files []map[string]any) []byte {
		doc := map[string]any{"files": files}
		b, _ := json.Marshal(doc)
		return b
	}

	entry := func(name string) map[string]any {
		return map[string]any{
			"fileName":  name,
			"fileTypes": []string{"BINARY"},
			"checksums": []map[string]string{
				{"algorithm": "SHA256", "checksumValue": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			},
		}
	}

	tests := []struct {
		name     string
		fileName string
		wantIncl bool
	}{
		{"absolute path", "/usr/bin/hello", true},
		{"SPDX dotslash", "./usr/bin/hello", true},
		{"relative traversal", "../../etc/shadow", false},
		{"dot-dot in middle", "./usr/../../etc/passwd", false},
		{"bare relative", "bin/hello", true},
		{"just dotdot", "..", false},
		{"dotdot slash", "../", false},
		{"empty filename", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomData := makeSBOM([]map[string]any{entry(tt.fileName)})
			files, err := ParseFiles(sbomData)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			found := false
			for _, f := range files {
				if f.FileName == tt.fileName {
					found = true
				}
			}
			if found != tt.wantIncl {
				t.Errorf("ParseFiles included=%v, want included=%v for fileName=%q", found, tt.wantIncl, tt.fileName)
			}
		})
	}
}
