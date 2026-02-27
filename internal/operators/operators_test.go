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
	"testing"
)

func TestDigestTracker_RefCounting(t *testing.T) {
	dt := newDigestState()
	digest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Simulate first container
	dt.mu.Lock()
	dt.digestEntries[digest] = &digestMapEntry{innerMap: nil, refCount: 1}
	dt.containerDigests[1000] = digest
	dt.mu.Unlock()

	// Simulate second container with same digest
	dt.mu.Lock()
	entry := dt.digestEntries[digest]
	entry.refCount++
	dt.containerDigests[2000] = digest
	dt.mu.Unlock()

	if entry.refCount != 2 {
		t.Fatalf("expected refCount 2, got %d", entry.refCount)
	}

	// Remove first container
	dt.mu.Lock()
	d, ok := dt.containerDigests[1000]
	if !ok || d != digest {
		t.Fatal("container 1000 not found in containerDigests")
	}
	delete(dt.containerDigests, 1000)
	dt.digestEntries[digest].refCount--
	dt.mu.Unlock()

	if dt.digestEntries[digest].refCount != 1 {
		t.Fatalf("expected refCount 1, got %d", dt.digestEntries[digest].refCount)
	}

	// Remove second container
	dt.mu.Lock()
	delete(dt.containerDigests, 2000)
	dt.digestEntries[digest].refCount--
	if dt.digestEntries[digest].refCount == 0 {
		delete(dt.digestEntries, digest)
	}
	dt.mu.Unlock()

	if _, exists := dt.digestEntries[digest]; exists {
		t.Fatal("expected digest entry to be removed after last container")
	}
}
