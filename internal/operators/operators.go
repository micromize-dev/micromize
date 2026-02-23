package operators

import (
	"fmt"
	"log/slog"

	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	"github.com/micromize-dev/micromize/internal/localmanager"
)

// DataOperator is an alias for igoperators.DataOperator to avoid direct dependency in main
type DataOperator = igoperators.DataOperator

func NewLocalManager(extraOpts ...localmanager.ContainerCollectionOption) (*localmanager.LocalManager, error) {
	slog.Debug("Initializing local manager operator")
	host.Init(host.Config{})
	localManagerOp := localmanager.New(extraOpts...)
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
