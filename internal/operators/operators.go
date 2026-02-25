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
	if err := host.Init(host.Config{}); err != nil {
		return nil, fmt.Errorf("init host: %w", err)
	}
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
	innerMaps := &sync.Map{} // mntns_id -> *ebpf.Map (for cleanup)

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
					handleContainerCreated(ctx, gadgetCtx, sbomFetcher, innerMaps, containerConfigField, containerIDField, mntnsIDField, data)
				case "REMOVED":
					handleContainerRemoved(gadgetCtx, innerMaps, mntnsIDField, data)
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

func handleContainerCreated(ctx context.Context, gadgetCtx igoperators.GadgetContext, fetcher *sbom.Fetcher, innerMaps *sync.Map, configField datasource.FieldAccessor, containerIDField datasource.FieldAccessor, mntnsIDField datasource.FieldAccessor, data datasource.Data) {
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

	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sbomData, err := fetcher.FetchForImage(fetchCtx, imageRef)
	if err != nil {
		slog.Error("Failed to fetch SBOM", "error", err)
		return
	}
	if sbomData != nil {
		slog.Debug("SBOM fetched for container image", "image", imageRef, "size", len(sbomData))

		files, err := sbom.ParseFiles(sbomData)
		if err != nil {
			slog.Error("Failed to parse SBOM files", "error", err)
			return
		}
		for _, f := range files {
			slog.Debug("SBOM binary file", "image", imageRef, "file", f.FileName, "sha256", f.SHA256)
		}

		if mntnsIDField != nil && len(files) > 0 {
			populateExpectedHashes(gadgetCtx, innerMaps, mntnsIDField, data, files)
		}
	}
}

// Keep in sync with gadgets/binary-attestation/program.bpf.h
const (
	expectedHashesMapName = "map/expected_hashes"
	maxAllowedFileHashes  = 512
	sha256HashSize        = 32
	maxFilepathLen        = 64
)

func populateExpectedHashes(gadgetCtx igoperators.GadgetContext, innerMaps *sync.Map, mntnsIDField datasource.FieldAccessor, data datasource.Data, files []sbom.FileInfo) {
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

	mntnsID, err := mntnsIDField.Uint64(data)
	if err != nil {
		slog.Error("Failed to read mntns_id field", "error", err)
		return
	}

	// Create a new inner map for this mount namespace
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

	// Insert the inner map into the outer map keyed by mntns_id
	if err := outerMap.Put(mntnsID, uint32(innerMap.FD())); err != nil {
		slog.Error("Failed to insert inner map into expected_hashes", "mntns_id", mntnsID, "error", err)
		if err := innerMap.Close(); err != nil {
			slog.Error("Failed to close inner BPF map", "mntns_id", mntnsID, "error", err)
		}
		return
	}

	// Track the inner map for cleanup on container removal
	innerMaps.Store(mntnsID, innerMap)

	slog.Debug("Populated expected_hashes map", "mntns_id", mntnsID, "entries", len(files))
}

func handleContainerRemoved(gadgetCtx igoperators.GadgetContext, innerMaps *sync.Map, mntnsIDField datasource.FieldAccessor, data datasource.Data) {
	if mntnsIDField == nil {
		slog.Debug("mntns_id field not available, cannot clean up expected_hashes for removed container")
		return
	}

	mntnsID, err := mntnsIDField.Uint64(data)
	if err != nil {
		slog.Debug("Failed to read mntns_id on container removal", "error", err)
		return
	}

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

	if val, loaded := innerMaps.LoadAndDelete(mntnsID); loaded {
		if m, ok := val.(*ebpf.Map); ok && m != nil {
			if err := m.Close(); err != nil {
				slog.Debug("Failed to close inner BPF map on container removal", "mntns_id", mntnsID, "error", err)
			}
		}
	}

	slog.Info("Cleaned up expected_hashes for removed container", "mntns_id", mntnsID)
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
