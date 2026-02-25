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

package runtime

import (
	"fmt"
	"log/slog"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// Manager handles runtime initialization and gadget execution
type Manager struct {
	runtime *local.Runtime
}

// NewManager creates a new runtime manager
func NewManager() (*Manager, error) {
	slog.Debug("Initializing runtime manager")
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return nil, fmt.Errorf("runtime init: %w", err)
	}

	return &Manager{
		runtime: runtime,
	}, nil
}

// RunGadget runs a gadget with the given context and parameters
func (m *Manager) RunGadget(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
	slog.Debug("Running gadget", "image", gadgetCtx.ImageName())
	return m.runtime.RunGadget(gadgetCtx, nil, params)
}

// Close cleans up runtime resources
func (m *Manager) Close() {
	slog.Debug("Closing runtime manager")
	if err := m.runtime.Close(); err != nil {
		slog.Error("Error closing runtime", "error", err)
	}
}
