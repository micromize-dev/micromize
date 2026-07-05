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
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

var eventDescriptions = map[uint32]string{
	eventTypeFSProcfsAccess:           "Procfs access blocked",
	eventTypeFSExecOutsideRoot:        "Execution outside container rootfs blocked",
	eventTypeCapNamespaceCreate:       "Namespace creation blocked",
	eventTypeCapModuleLoad:            "Kernel module load blocked",
	eventTypePtraceAccess:             "Ptrace access blocked",
	eventTypePtraceTraceme:            "Ptrace traceme blocked",
	eventTypeUnattestedBinary:         "Unattested binary executed",
	eventTypeHashMismatch:             "Binary hash mismatch detected",
	eventTypeUnattestedSharedObject:   "Unattested shared object loaded",
	eventTypeSharedObjectHashMismatch: "Shared object hash mismatch detected",
	eventTypeSocketAFAlgCreate:        "AF_ALG socket creation blocked",
	eventTypeSocketAFAlgBind:          "AF_ALG socket bind blocked",
	eventTypeCapModuleAutoload:        "Kernel module auto-load blocked",
	eventTypeSocketAFKeyCreate:        "AF_KEY (PF_KEY IPsec) socket creation blocked",
	eventTypeSocketXfrmNetlinkCreate:  "XFRM/IPsec netlink socket creation blocked",
	eventTypeSocketFamilyDeniedCreate: "Socket family denied (create)",
	eventTypeSocketFamilyDeniedBind:   "Socket family denied (bind)",
}

var eventEmojis = map[uint32]string{}

var capNames = map[int32]string{
	16: "CAP_SYS_MODULE",
	21: "CAP_SYS_ADMIN",
}

type eventFields struct {
	eventType    datasource.FieldAccessor
	timestampRaw datasource.FieldAccessor
	filename     datasource.FieldAccessor

	// Process
	comm       datasource.FieldAccessor
	pid        datasource.FieldAccessor
	parentComm datasource.FieldAccessor
	parentPid  datasource.FieldAccessor
	uid        datasource.FieldAccessor
	gid        datasource.FieldAccessor

	// K8s enrichment
	k8sNamespace     datasource.FieldAccessor
	k8sPodName       datasource.FieldAccessor
	k8sContainerName datasource.FieldAccessor

	// Runtime enrichment
	runtimeContainerName      datasource.FieldAccessor
	runtimeContainerImageName datasource.FieldAccessor

	// Cap-restrict specific
	cap     datasource.FieldAccessor
	syscall datasource.FieldAccessor

	// socket-restrict specific
	algType datasource.FieldAccessor
	algName datasource.FieldAccessor

	// cap-restrict module autoload
	moduleName datasource.FieldAccessor
}

var (
	outputMu       sync.Mutex
	bootTimeOffset time.Time
	bootTimeOnce   sync.Once
)

func getBootTimeOffset() time.Time {
	bootTimeOnce.Do(func() {
		bootTimeOffset = readBootTime()
	})
	return bootTimeOffset
}

func readBootTime() time.Time {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "btime ") {
			var sec int64
			if _, err := fmt.Sscanf(line, "btime %d", &sec); err == nil {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

func eventTimestamp(f *eventFields, data datasource.Data) string {
	if f.timestampRaw != nil {
		if ns, err := f.timestampRaw.Uint64(data); err == nil && ns > 0 {
			boot := getBootTimeOffset()
			if !boot.IsZero() {
				wallTime := boot.Add(time.Duration(ns))
				return wallTime.Format("15:04:05")
			}
		}
	}
	return time.Now().Format("15:04:05")
}

// NewOutputOperator creates an operator that prints security events in a
// human-readable format to stdout, replacing the default JSON CLI output.
func NewOutputOperator() igoperators.DataOperator {
	slog.Debug("Creating output operator")
	return simple.New("outputOperator",
		simple.WithPriority(math.MaxInt),
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				if ds.Name() == "containers" {
					continue
				}

				etField := ds.GetField("event_type")
				if etField == nil {
					continue
				}

				fields := collectEventFields(ds, etField)
				f := fields

				if err := ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					formatAndPrintEvent(f, data)
					return nil
				}, math.MaxInt); err != nil {
					return fmt.Errorf("subscribing to %s for output: %w", ds.Name(), err)
				}

				slog.Debug("Output operator registered", "datasource", ds.Name())
			}
			return nil
		}),
	)
}

func collectEventFields(ds datasource.DataSource, etField datasource.FieldAccessor) *eventFields {
	f := &eventFields{eventType: etField}

	f.timestampRaw = ds.GetField("timestamp_raw")
	f.filename = ds.GetField("filename")

	f.comm = ds.GetField("process.comm")
	f.pid = ds.GetField("process.pid")
	f.parentComm = ds.GetField("process.parent.comm")
	f.parentPid = ds.GetField("process.parent.pid")
	f.uid = ds.GetField("process.creds.uid")
	f.gid = ds.GetField("process.creds.gid")

	f.k8sNamespace = ds.GetField("k8s.namespace")
	f.k8sPodName = ds.GetField("k8s.podName")
	f.k8sContainerName = ds.GetField("k8s.containerName")

	f.runtimeContainerName = ds.GetField("runtime.containerName")
	f.runtimeContainerImageName = ds.GetField("runtime.containerImageName")

	f.cap = ds.GetField("cap")
	f.syscall = ds.GetField("syscall")
	f.algType = ds.GetField("alg_type")
	f.algName = ds.GetField("alg_name")
	f.moduleName = ds.GetField("module_name")

	return f
}

func formatAndPrintEvent(f *eventFields, data datasource.Data) {
	eventType, err := f.eventType.Uint32(data)
	if err != nil {
		return
	}

	emoji := eventEmojis[eventType]
	if emoji == "" {
		emoji = "🚫"
	}

	desc := eventDescriptions[eventType]
	if desc == "" {
		desc = fmt.Sprintf("Unknown event (type=%d)", eventType)
	}

	container := containerIdentity(f, data)
	ts := eventTimestamp(f, data)

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n\n   %s %s: %s", emoji, ts, desc)
	if container != "" {
		fmt.Fprintf(&sb, " in %s", container)
	}

	if filename := fieldStr(f.filename, data); filename != "" {
		fmt.Fprintf(&sb, ". Filename: %s", filename)
	}
	if algType := fieldStr(f.algType, data); algType != "" {
		fmt.Fprintf(&sb, ". AF_ALG type: %s", algType)
		if algName := fieldStr(f.algName, data); algName != "" {
			fmt.Fprintf(&sb, ". Algorithm: %s", algName)
		}
	}
	if modName := fieldStr(f.moduleName, data); modName != "" {
		fmt.Fprintf(&sb, ". Module: %s", modName)
	}

	// Show image name only for Docker (non-k8s) environments
	if fieldStr(f.k8sNamespace, data) == "" {
		if imageName := fieldStr(f.runtimeContainerImageName, data); imageName != "" {
			fmt.Fprintf(&sb, "\n      Image: %s", imageName)
		}
	}

	// Cap-restrict details
	if f.cap != nil {
		if capVal, err := f.cap.Int32(data); err == nil {
			capName := capNames[capVal]
			if capName != "" {
				fmt.Fprintf(&sb, "\n      Capability: %s", capName)
			} else {
				fmt.Fprintf(&sb, "\n      Capability: %d", capVal)
			}
			if f.syscall != nil {
				if syscallVal, err := f.syscall.Int32(data); err == nil {
					fmt.Fprintf(&sb, "  Syscall: %d", syscallVal)
				}
			}
		}
	}

	// Process evidence line
	evidence := processEvidence(f, data)
	if evidence != "" {
		fmt.Fprintf(&sb, "\n      %s", evidence)
	}

	outputMu.Lock()
	if _, err := fmt.Fprintln(os.Stdout, sb.String()); err != nil {
		slog.Error("Failed to write event output", "error", err)
	}
	outputMu.Unlock()
}

func containerIdentity(f *eventFields, data datasource.Data) string {
	ns := fieldStr(f.k8sNamespace, data)
	pod := fieldStr(f.k8sPodName, data)
	ctr := fieldStr(f.k8sContainerName, data)

	if ns != "" && pod != "" && ctr != "" {
		return "namespace: " + ns + " pod: " + pod + "/" + ctr
	}
	if ns != "" && pod != "" {
		return "namespace: " + ns + " pod: " + pod
	}

	if name := fieldStr(f.runtimeContainerName, data); name != "" {
		return name
	}
	return ""
}

func processEvidence(f *eventFields, data datasource.Data) string {
	var parts []string

	if comm := fieldStr(f.comm, data); comm != "" {
		parts = append(parts, "comm="+comm)
	}
	if pid := fieldUint(f.pid, data); pid != "" {
		parts = append(parts, "pid="+pid)
	}
	if ppid := fieldUint(f.parentPid, data); ppid != "" {
		parts = append(parts, "ppid="+ppid)
	}
	if uid := fieldUint(f.uid, data); uid != "" {
		parts = append(parts, "uid="+uid)
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "  ")
}

func fieldStr(fa datasource.FieldAccessor, data datasource.Data) string {
	if fa == nil {
		return ""
	}
	val, err := fa.String(data)
	if err != nil {
		return ""
	}
	return val
}

func fieldUint(fa datasource.FieldAccessor, data datasource.Data) string {
	if fa == nil {
		return ""
	}
	val, err := fa.Uint32(data)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d", val)
}
