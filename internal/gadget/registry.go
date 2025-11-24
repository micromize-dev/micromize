package gadget

import (
	"context"
	"fmt"

	"github.com/micromize-dev/micromize/internal/runtime"
)

// GadgetConfig holds the configuration for a single gadget
type GadgetConfig struct {
	Bytes     []byte
	ImageName string
	Params    map[string]string
	Context   *ContextManager // Optional context manager override
}

// Registry manages multiple gadgets and their execution
type Registry struct {
	defaultContextManager *ContextManager
	runtimeManager        *runtime.Manager
	gadgets               map[string]*GadgetConfig
}

// NewRegistry creates a new gadget registry
func NewRegistry(defaultContextManager *ContextManager, runtimeManager *runtime.Manager) *Registry {
	return &Registry{
		defaultContextManager: defaultContextManager,
		runtimeManager:        runtimeManager,
		gadgets:               make(map[string]*GadgetConfig),
	}
}

// Register adds a new gadget to the registry
func (r *Registry) Register(name string, config *GadgetConfig) {
	r.gadgets[name] = config
}

// RunAll starts all registered gadgets
func (r *Registry) RunAll(ctx context.Context) error {
	for name, config := range r.gadgets {
		contextManager := r.defaultContextManager
		if config.Context != nil {
			contextManager = config.Context
		}

		gadgetCtx, err := contextManager.CreateContext(ctx, config.Bytes, config.ImageName)
		if err != nil {
			return fmt.Errorf("creating context for gadget %s: %w", name, err)
		}

		go func(name string, config *GadgetConfig) {
			if err := r.runtimeManager.RunGadget(gadgetCtx, config.Params); err != nil {
				fmt.Printf("Error running gadget %s: %v\n", name, err)
			}
		}(name, config)
	}
	return nil
}
