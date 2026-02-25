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

package gadget

import (
	"context"
	"fmt"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"golang.org/x/sync/errgroup"
)

// RuntimeManager defines the interface for running gadgets
type RuntimeManager interface {
	RunGadget(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error
}

// GadgetContextCreator defines the interface for creating gadget contexts
type GadgetContextCreator interface {
	CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error)
}

// GadgetConfig holds the configuration for a single gadget
type GadgetConfig struct {
	Bytes     []byte
	ImageName string
	Params    map[string]string
	Context   GadgetContextCreator // Optional context manager override
}

// Registry manages multiple gadgets and their execution
type Registry struct {
	defaultContextManager GadgetContextCreator
	runtimeManager        RuntimeManager
	gadgets               map[string]*GadgetConfig
}

// NewRegistry creates a new gadget registry
func NewRegistry(defaultContextManager GadgetContextCreator, runtimeManager RuntimeManager) *Registry {
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

// RunAll starts all registered gadgets and returns an errgroup that the caller
// can Wait() on. If any gadget fails, the errgroup's context is canceled,
// signaling other gadgets to stop.
func (r *Registry) RunAll(ctx context.Context) (*errgroup.Group, error) {
	g, gCtx := errgroup.WithContext(ctx)

	// Pre-pass: create all gadget contexts before starting any goroutines.
	// This ensures that if CreateContext fails, no goroutines have been started.
	type gadgetEntry struct {
		name      string
		config    *GadgetConfig
		gadgetCtx *gadgetcontext.GadgetContext
	}

	entries := make([]gadgetEntry, 0, len(r.gadgets))
	for name, config := range r.gadgets {
		contextManager := r.defaultContextManager
		if config.Context != nil {
			contextManager = config.Context
		}

		gadgetCtx, err := contextManager.CreateContext(gCtx, config.Bytes, config.ImageName)
		if err != nil {
			return nil, fmt.Errorf("creating context for gadget %s: %w", name, err)
		}

		entries = append(entries, gadgetEntry{name: name, config: config, gadgetCtx: gadgetCtx})
	}

	for _, e := range entries {
		g.Go(func() error {
			if err := r.runtimeManager.RunGadget(e.gadgetCtx, e.config.Params); err != nil {
				return fmt.Errorf("running gadget %s: %w", e.name, err)
			}
			return nil
		})
	}

	return g, nil
}
