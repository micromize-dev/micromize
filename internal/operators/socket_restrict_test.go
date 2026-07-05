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

package operators

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// numericList builds a comma-separated string of the integers [start, start+n).
func numericList(start, n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, strconv.Itoa(start+i))
	}
	return strings.Join(parts, ",")
}

func sortedU16(in []uint16) []uint16 {
	out := append([]uint16(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedU32(in []uint32) []uint32 {
	out := append([]uint32(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestParseSocketDenyFamilies(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint16
		wantErr bool
	}{
		{name: "empty", input: "", want: nil},
		{name: "whitespace only", input: "  ,  ", want: nil},
		{name: "single name", input: "AF_ALG", want: []uint16{38}},
		{name: "case insensitive", input: "af_alg", want: []uint16{38}},
		{name: "decimal", input: "38", want: []uint16{38}},
		{
			name:  "mixed names and numbers",
			input: " AF_ALG ,30, AF_VSOCK",
			want:  []uint16{30, 38, 40},
		},
		{
			name:  "duplicates collapsed",
			input: "AF_ALG,38,AF_ALG",
			want:  []uint16{38},
		},
		{name: "unknown name", input: "AF_NOPE", wantErr: true},
		{name: "out of range", input: "1000000", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSocketDenyFamilies(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSocketDenyFamilies(%q) err=%v, wantErr=%v",
					tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(sortedU16(got), sortedU16(tt.want)) {
				t.Errorf("ParseSocketDenyFamilies(%q) = %v, want %v",
					tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSocketDenyNetlinkProtocols(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint32
		wantErr bool
	}{
		{name: "empty default", input: "", want: nil},
		{
			name:  "all four common opt-ins",
			input: "NETLINK_NETFILTER,NETLINK_XFRM,NETLINK_AUDIT,NETLINK_KOBJECT_UEVENT",
			want:  []uint32{6, 9, 12, 15},
		},
		{name: "case insensitive", input: "netlink_netfilter", want: []uint32{12}},
		{name: "decimal", input: "12", want: []uint32{12}},
		{name: "unknown", input: "NETLINK_NOPE", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSocketDenyNetlinkProtocols(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSocketDenyNetlinkProtocols(%q) err=%v, wantErr=%v",
					tt.input, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(sortedU32(got), sortedU32(tt.want)) {
				t.Errorf("ParseSocketDenyNetlinkProtocols(%q) = %v, want %v",
					tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSocketDenyFamiliesCapacity(t *testing.T) {
	// Exactly at capacity is allowed.
	if _, err := ParseSocketDenyFamilies(numericList(1, maxDeniedFamilies)); err != nil {
		t.Fatalf("ParseSocketDenyFamilies at capacity (%d) returned error: %v", maxDeniedFamilies, err)
	}
	// One over capacity must be rejected with a clear error.
	got, err := ParseSocketDenyFamilies(numericList(1, maxDeniedFamilies+1))
	if err == nil {
		t.Fatalf("ParseSocketDenyFamilies over capacity (%d) did not error", maxDeniedFamilies+1)
	}
	if got != nil {
		t.Errorf("ParseSocketDenyFamilies over capacity returned non-nil slice: %v", got)
	}
}

func TestParseSocketDenyNetlinkProtocolsCapacity(t *testing.T) {
	// Exactly at capacity is allowed.
	if _, err := ParseSocketDenyNetlinkProtocols(numericList(0, maxDeniedNetlinkProtocols)); err != nil {
		t.Fatalf("ParseSocketDenyNetlinkProtocols at capacity (%d) returned error: %v", maxDeniedNetlinkProtocols, err)
	}
	// One over capacity must be rejected with a clear error.
	got, err := ParseSocketDenyNetlinkProtocols(numericList(0, maxDeniedNetlinkProtocols+1))
	if err == nil {
		t.Fatalf("ParseSocketDenyNetlinkProtocols over capacity (%d) did not error", maxDeniedNetlinkProtocols+1)
	}
	if got != nil {
		t.Errorf("ParseSocketDenyNetlinkProtocols over capacity returned non-nil slice: %v", got)
	}
}
