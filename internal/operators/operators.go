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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	api "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
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
	eventTypeSocketAFAlgCreate        = 11
	eventTypeSocketAFAlgBind          = 12
	eventTypeCapModuleAutoload        = 13
	eventTypeSocketAFKeyCreate        = 14
	eventTypeSocketXfrmNetlinkCreate  = 15
	eventTypeSocketFamilyDeniedCreate = 20
	eventTypeSocketFamilyDeniedBind   = 21
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
	eventTypeSocketAFAlgCreate:        "af_alg_socket_create",
	eventTypeSocketAFAlgBind:          "af_alg_socket_bind",
	eventTypeCapModuleAutoload:        "module_autoload",
	eventTypeSocketAFKeyCreate:        "af_key_socket_create",
	eventTypeSocketXfrmNetlinkCreate:  "xfrm_netlink_socket_create",
	eventTypeSocketFamilyDeniedCreate: "socket_family_denied_create",
	eventTypeSocketFamilyDeniedBind:   "socket_family_denied_bind",
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
