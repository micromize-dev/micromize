package gadget

import (
	"bytes"
	"context"
	"fmt"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/quay/claircore/pkg/tarfs"
	orasoci "oras.land/oras-go/v2/content/oci"
)

// ContextManager handles the creation and management of gadget contexts
type ContextManager struct {
	operators []operators.DataOperator
}

// NewContextManager creates a new ContextManager with the given operators
func NewContextManager(operators []operators.DataOperator) *ContextManager {
	return &ContextManager{
		operators: operators,
	}
}

// CreateContext creates a new gadget context with the given configuration
func (cm *ContextManager) CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error) {
	// Create OCI target from gadget bytes
	reader := bytes.NewReader(gadgetBytes)
	fs, err := tarfs.New(reader)
	if err != nil {
		return nil, fmt.Errorf("creating tarfs: %w", err)
	}

	target, err := orasoci.NewFromFS(ctx, fs)
	if err != nil {
		return nil, fmt.Errorf("getting oci store from bytes: %w", err)
	}

	// Create gadget context with operators
	gadgetCtx := gadgetcontext.New(
		ctx,
		gadgetImage,
		gadgetcontext.WithDataOperators(cm.operators...),
		gadgetcontext.WithOrasReadonlyTarget(target),
	)

	return gadgetCtx, nil
}
