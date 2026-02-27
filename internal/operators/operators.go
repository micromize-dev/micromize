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
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	api "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	"github.com/micromize-dev/micromize/internal/sbom"
)

// DataOperator is an alias for igoperators.DataOperator to avoid direct dependency in main
type DataOperator = igoperators.DataOperator

func NewLocalManager() (igoperators.DataOperator, error) {
	slog.Debug("Initializing local manager operator")
	host.Init(host.Config{})
	localManagerOp := localmanager.LocalManagerOperator
	localManagerParams := localManagerOp.GlobalParamDescs().ToParams()

	if err := localManagerOp.Init(localManagerParams); err != nil {
		return nil, fmt.Errorf("init local manager: %w", err)
	}
	return localManagerOp, nil
}

// NewOCIHandler creates and returns the OCI handler operator
func NewOCIHandler() igoperators.DataOperator {
	slog.Debug("Creating OCI handler operator")
	return ocihandler.OciHandler
}

// NewCLIOperator creates and returns the CLI operator
func NewCLIOperator() igoperators.DataOperator {
	slog.Debug("Creating CLI operator")
	return clioperator.CLIOperator
}

// NewImaOperator creates and returns the IMA operator
func NewImaOperator() igoperators.DataOperator {
	slog.Debug("Creating IMA operator")
	opPriority := math.MaxInt
	sbomFetcher := sbom.NewFetcher()
	digestState := newDigestState()

	operatorOptions := []simple.Option{
		simple.WithPriority(opPriority),
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			ctx := gadgetCtx.Context()
			containersDatasource := gadgetCtx.GetDataSources()["containers"]
			if containersDatasource == nil {
				slog.Debug("IMA Operator: containers datasource not available, skipping")
				return nil
			}

			eventTypeField := containersDatasource.GetField("event_type")
			if eventTypeField == nil {
				return fmt.Errorf("containers datasource missing event_type field")
			}

			containerConfigField := containersDatasource.GetField("container_config")
			if containerConfigField == nil {
				return fmt.Errorf("containers datasource missing container_config field")
			}

			containerIDField := containersDatasource.GetField("container_id")

			mntnsIDField := containersDatasource.GetField("mntns_id")

			if err := containersDatasource.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				eventType, err := eventTypeField.String(data)
				if err != nil {
					return fmt.Errorf("getting event_type value: %w", err)
				}
				switch eventType {
				case "CREATED":
					handleContainerCreated(ctx, gadgetCtx, sbomFetcher, digestState, containerConfigField, containerIDField, mntnsIDField, data)
				case "DELETED":
					handleContainerRemoved(gadgetCtx, digestState, mntnsIDField, data)
				}
				return nil
			}, opPriority); err != nil {
				return fmt.Errorf("subscribing to containers datasource: %w", err)
			}
			return nil
		}),
	}
	return simple.New("imaOperator", operatorOptions...)
}

// digestMapEntry tracks a shared inner BPF map for a given image digest.
type digestMapEntry struct {
	innerMap *ebpf.Map
	refCount int
}

// digestTracker manages the mapping between containers (mntns_id) and their
// image digests, with reference counting for shared inner BPF maps.
type digestTracker struct {
	mu               sync.Mutex
	digestEntries    map[string]*digestMapEntry // digest string → entry
	containerDigests map[uint64]string          // mntns_id → digest string
}

func newDigestState() *digestTracker {
	return &digestTracker{
		digestEntries:    make(map[string]*digestMapEntry),
		containerDigests: make(map[uint64]string),
	}
}

func handleContainerCreated(ctx context.Context, gadgetCtx igoperators.GadgetContext, fetcher *sbom.Fetcher, dt *digestTracker, configField datasource.FieldAccessor, containerIDField datasource.FieldAccessor, mntnsIDField datasource.FieldAccessor, data datasource.Data) {
	ociConfig, err := configField.String(data)
	if err != nil {
		slog.Debug("Failed to read container_config field", "error", err)
		return
	}

	imageRef, err := sbom.ImageRefFromOCIConfig(ociConfig)
	if err != nil {
		slog.Debug("Failed to parse OCI config", "error", err)
		return
	}

	// Fallback: read image ref from Docker's config.v2.json when
	// OCI annotations don't contain the image name (plain Docker).
	if imageRef == "" && containerIDField != nil {
		containerID, _ := containerIDField.String(data)
		imageRef = sbom.ImageRefFromDockerConfig(containerID)
	}

	imageRef = sbom.NormalizeImageRef(imageRef)

	if mntnsIDField == nil {
		slog.Debug("mntns_id field not available, cannot populate BPF maps")
		return
	}

	mntnsID, err := mntnsIDField.Uint64(data)
	if err != nil {
		slog.Error("Failed to read mntns_id field", "error", err)
		return
	}

	// Resolve image digest (lightweight HEAD request).
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	digest, err := sbom.ResolveDigest(fetchCtx, imageRef)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)
		return
	}

	// Check if we already have an inner map for this digest (another
	// container with the same image is already running).
	dt.mu.Lock()
	if entry, ok := dt.digestEntries[digest]; ok {
		entry.refCount++
		dt.containerDigests[mntnsID] = digest
		innerMap := entry.innerMap
		dt.mu.Unlock()

		// Reuse the same inner map FD in expected_hashes for this mntns_id.
		insertSharedInnerMap(gadgetCtx, mntnsID, innerMap)
		slog.Debug("Reusing existing inner map", "image", imageRef, "digest", digest, "mntns_id", mntnsID, "refCount", entry.refCount)
		return
	}
	dt.mu.Unlock()

	// First container with this digest — fetch and parse the SBOM.
	// Use FetchForDigest to avoid a redundant HEAD request.
	files, err := fetcher.FetchForDigest(fetchCtx, imageRef, digest)
	if err != nil {
		slog.Error("Failed to fetch SBOM", "error", err)
		return
	}

	if len(files) > 0 {
		slog.Debug("SBOM fetched for container image", "image", imageRef, "digest", digest, "files", len(files))
		for _, f := range files {
			slog.Debug("SBOM binary file", "image", imageRef, "file", f.FileName, "sha256", f.SHA256)
		}

		// Re-check under lock: another goroutine may have created the
		// entry while we were fetching.
		dt.mu.Lock()
		if entry, ok := dt.digestEntries[digest]; ok {
			entry.refCount++
			dt.containerDigests[mntnsID] = digest
			innerMap := entry.innerMap
			dt.mu.Unlock()

			insertSharedInnerMap(gadgetCtx, mntnsID, innerMap)
			slog.Debug("Reusing inner map (created during fetch)", "image", imageRef, "digest", digest, "mntns_id", mntnsID, "refCount", entry.refCount)
			return
		}
		// Hold the lock through populateExpectedHashes to prevent
		// two goroutines from both creating inner maps for the same digest.
		populateExpectedHashes(gadgetCtx, dt, mntnsID, digest, files)
		dt.mu.Unlock()
	}
}

// Keep in sync with gadgets/binary-attestation/program.bpf.h
const (
	expectedHashesMapName = "map/expected_hashes"
	maxAllowedFileHashes  = 512
	sha256HashSize        = 32
	maxFilepathLen        = 64
)

func populateExpectedHashes(gadgetCtx igoperators.GadgetContext, dt *digestTracker, mntnsID uint64, digest string, files []sbom.FileInfo) {
	outerMapVar, ok := gadgetCtx.GetVar(expectedHashesMapName)
	if !ok {
		slog.Debug("expected_hashes map not available in gadget context, skipping map population")
		return
	}

	outerMap, ok := outerMapVar.(*ebpf.Map)
	if !ok || outerMap == nil {
		slog.Debug("expected_hashes map is not a valid *ebpf.Map, skipping")
		return
	}

	// Create a new inner map for this digest
	innerMapSpec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(maxFilepathLen),
		ValueSize:  uint32(sha256HashSize),
		MaxEntries: maxAllowedFileHashes,
	}

	innerMap, err := ebpf.NewMap(innerMapSpec)
	if err != nil {
		slog.Error("Failed to create inner BPF map", "error", err)
		return
	}

	// Populate the inner map with file hashes from the SBOM
	for _, f := range files {
		var key [maxFilepathLen]byte

		if len(f.FileName) > maxFilepathLen {
			slog.Error("SBOM file path exceeds maximum length", "file", f.FileName, "length", len(f.FileName))
			continue
		}
		// Normalize SBOM filename to match kernel dentry path format.
		// SPDX filenames use "./" prefix (e.g. "./hello"), while the kernel
		// returns absolute paths from the mount root (e.g. "/hello").
		name := f.FileName
		name = strings.TrimPrefix(name, ".")
		if !strings.HasPrefix(name, "/") {
			name = "/" + name
		}
		copy(key[:], name)

		var value [sha256HashSize]byte
		decoded, err := hex.DecodeString(f.SHA256)
		if err != nil {
			slog.Error("Failed to decode SHA256 hash", "file", f.FileName, "error", err)
			continue
		}
		if len(decoded) != sha256HashSize {
			slog.Error("Invalid SHA256 hash length", "file", f.FileName, "length", len(decoded))
			continue
		}
		copy(value[:], decoded)

		if err := innerMap.Put(key, value); err != nil {
			slog.Error("Failed to insert entry into inner BPF map", "file", f.FileName, "error", err)
		}
	}

	// Insert the inner map into expected_hashes keyed by mntns_id
	if err := outerMap.Put(mntnsID, uint32(innerMap.FD())); err != nil {
		slog.Error("Failed to insert inner map into expected_hashes", "mntns_id", mntnsID, "error", err)
		innerMap.Close()
		return
	}

	// Track the inner map by digest for sharing with future containers.
	// Caller holds dt.mu.
	dt.digestEntries[digest] = &digestMapEntry{innerMap: innerMap, refCount: 1}
	dt.containerDigests[mntnsID] = digest

	slog.Debug("Populated expected_hashes map", "digest", digest, "mntns_id", mntnsID, "entries", len(files))
}

// insertSharedInnerMap inserts an existing inner map into expected_hashes
// for a new container that shares the same image digest.
func insertSharedInnerMap(gadgetCtx igoperators.GadgetContext, mntnsID uint64, innerMap *ebpf.Map) {
	outerMapVar, ok := gadgetCtx.GetVar(expectedHashesMapName)
	if !ok {
		slog.Debug("expected_hashes map not available in gadget context")
		return
	}
	outerMap, ok := outerMapVar.(*ebpf.Map)
	if !ok || outerMap == nil {
		slog.Debug("expected_hashes map is not a valid *ebpf.Map")
		return
	}

	if err := outerMap.Put(mntnsID, uint32(innerMap.FD())); err != nil {
		slog.Error("Failed to insert shared inner map into expected_hashes", "mntns_id", mntnsID, "error", err)
	}
}

func handleContainerRemoved(gadgetCtx igoperators.GadgetContext, dt *digestTracker, mntnsIDField datasource.FieldAccessor, data datasource.Data) {
	if mntnsIDField == nil {
		slog.Debug("mntns_id field not available, cannot clean up expected_hashes for removed container")
		return
	}

	mntnsID, err := mntnsIDField.Uint64(data)
	if err != nil {
		slog.Debug("Failed to read mntns_id on container removal", "error", err)
		return
	}

	// Remove mntns_id from expected_hashes BPF map
	outerMapVar, ok := gadgetCtx.GetVar(expectedHashesMapName)
	if !ok {
		return
	}
	outerMap, ok := outerMapVar.(*ebpf.Map)
	if !ok || outerMap == nil {
		return
	}

	if err := outerMap.Delete(mntnsID); err != nil {
		slog.Debug("Failed to delete entry from expected_hashes", "mntns_id", mntnsID, "error", err)
	}

	// Decrement ref count; close inner map when last container is removed
	dt.mu.Lock()
	digest, ok := dt.containerDigests[mntnsID]
	if !ok {
		dt.mu.Unlock()
		return
	}
	delete(dt.containerDigests, mntnsID)

	entry, exists := dt.digestEntries[digest]
	if !exists {
		dt.mu.Unlock()
		return
	}

	entry.refCount--
	if entry.refCount > 0 {
		dt.mu.Unlock()
		slog.Debug("Decremented digest refCount", "digest", digest, "mntns_id", mntnsID, "refCount", entry.refCount)
		return
	}

	// Last container using this digest — clean up the inner map.
	delete(dt.digestEntries, digest)
	dt.mu.Unlock()

	if entry.innerMap != nil {
		entry.innerMap.Close()
	}

	slog.Info("Cleaned up shared inner map for last container", "digest", digest, "mntns_id", mntnsID)
}

// Event type constants matching include/micromize/event_types.h
const (
	eventTypeUnknown                  = 0
	eventTypeFSProcfsAccess           = 1
	eventTypeFSExecOutsideRoot        = 2
	eventTypeCapNamespaceCreate       = 3
	eventTypeCapModuleLoad            = 4
	eventTypePtraceAccess             = 5
	eventTypePtraceTraceme            = 6
	eventTypeUnattestedBinary         = 7
	eventTypeHashMismatch             = 8
	eventTypeUnattestedSharedObject   = 9
	eventTypeSharedObjectHashMismatch = 10
)

var eventTypeNames = map[uint32]string{
	eventTypeUnknown:                  "unknown",
	eventTypeFSProcfsAccess:           "procfs_access",
	eventTypeFSExecOutsideRoot:        "exec_outside_rootfs",
	eventTypeCapNamespaceCreate:       "namespace_creation",
	eventTypeCapModuleLoad:            "module_load",
	eventTypePtraceAccess:             "ptrace_access",
	eventTypePtraceTraceme:            "ptrace_traceme",
	eventTypeUnattestedBinary:         "unattested_binary",
	eventTypeHashMismatch:             "hash_mismatch",
	eventTypeUnattestedSharedObject:   "unattested_shared_object",
	eventTypeSharedObjectHashMismatch: "shared_object_hash_mismatch",
}

// NewEventTypeOperator creates an operator that enriches events with a
// human-readable "reason" field derived from the numeric event_type.
func NewEventTypeOperator() igoperators.DataOperator {
	slog.Debug("Creating event type operator")
	return simple.New("eventTypeOperator",
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				eventTypeField := ds.GetField("event_type")
				if eventTypeField == nil {
					continue
				}

				reasonField, err := ds.AddField("reason", api.Kind_String)
				if err != nil {
					return fmt.Errorf("adding reason field to %s: %w", ds.Name(), err)
				}

				dsName := ds.Name()
				etField := eventTypeField
				rField := reasonField

				if err := ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					val, err := etField.Uint32(data)
					if err != nil {
						return nil
					}
					name, ok := eventTypeNames[val]
					if !ok {
						name = "unknown"
					}
					if err := rField.PutString(data, name); err != nil {
						slog.Debug("Failed to set reason field", "datasource", dsName, "error", err)
					}
					return nil
				}, 0); err != nil {
					return fmt.Errorf("subscribing to %s for event type enrichment: %w", dsName, err)
				}

				slog.Debug("Event type enrichment registered", "datasource", dsName)
			}
			return nil
		}),
	)
}
