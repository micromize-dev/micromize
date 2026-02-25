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
	"sync"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

type mockRuntimeManager struct {
	runGadgetFunc func(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error
}

func (m *mockRuntimeManager) RunGadget(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
	if m.runGadgetFunc != nil {
		return m.runGadgetFunc(gadgetCtx, params)
	}
	return nil
}

type mockContextCreator struct {
	createContextFunc func(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error)
}

func (m *mockContextCreator) CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImage string) (*gadgetcontext.GadgetContext, error) {
	if m.createContextFunc != nil {
		return m.createContextFunc(ctx, gadgetBytes, gadgetImage)
	}
	return gadgetcontext.New(ctx, gadgetImage), nil
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry(&mockContextCreator{}, &mockRuntimeManager{})
	config := &GadgetConfig{
		ImageName: "test-image",
	}
	r.Register("test", config)

	if len(r.gadgets) != 1 {
		t.Errorf("expected 1 gadget, got %d", len(r.gadgets))
	}
	if r.gadgets["test"] != config {
		t.Errorf("expected config %v, got %v", config, r.gadgets["test"])
	}
}

func TestRegistry_RunAll(t *testing.T) {
	done := make(chan struct{})
	var once sync.Once
	mockRuntime := &mockRuntimeManager{
		runGadgetFunc: func(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
			once.Do(func() {
				close(done)
			})
			return nil
		},
	}

	mockContext := &mockContextCreator{}
	r := NewRegistry(mockContext, mockRuntime)

	r.Register("test", &GadgetConfig{
		ImageName: "test-image",
		Params:    map[string]string{"foo": "bar"},
	})

	g, err := r.RunAll(context.Background())
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	if err := g.Wait(); err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}

	select {
	case <-done:
		// success
	default:
		t.Fatal("RunGadget was never called")
	}
}

func TestRegistry_RunAll_ErrorPropagation(t *testing.T) {
	mockRuntime := &mockRuntimeManager{
		runGadgetFunc: func(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
			return fmt.Errorf("gadget startup failed")
		},
	}

	mockContext := &mockContextCreator{}
	r := NewRegistry(mockContext, mockRuntime)

	r.Register("failing-gadget", &GadgetConfig{
		ImageName: "test-image",
		Params:    map[string]string{},
	})

	g, err := r.RunAll(context.Background())
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	err = g.Wait()
	if err == nil {
		t.Fatal("expected error from Wait, got nil")
	}

	expected := "running gadget failing-gadget: gadget startup failed"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestRegistry_RunAll_ContextCancellation(t *testing.T) {
	mockRuntime := &mockRuntimeManager{
		runGadgetFunc: func(gadgetCtx *gadgetcontext.GadgetContext, params map[string]string) error {
			// Simulate a long-running gadget that respects context cancellation
			<-gadgetCtx.Context().Done()
			return gadgetCtx.Context().Err()
		},
	}

	mockContext := &mockContextCreator{}
	r := NewRegistry(mockContext, mockRuntime)

	r.Register("long-running", &GadgetConfig{
		ImageName: "test-image",
		Params:    map[string]string{},
	})

	r.Register("another", &GadgetConfig{
		ImageName: "test-image",
		Params:    map[string]string{},
	})

	ctx, cancel := context.WithCancel(context.Background())
	g, err := r.RunAll(ctx)
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	// Cancel the context to simulate shutdown signal
	cancel()

	err = g.Wait()
	if err == nil {
		t.Fatal("expected error from Wait after cancellation, got nil")
	}
}
