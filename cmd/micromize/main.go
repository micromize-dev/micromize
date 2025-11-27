package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/micromize-dev/micromize/internal/gadget"
	"github.com/micromize-dev/micromize/internal/operators"
	"github.com/micromize-dev/micromize/internal/runtime"
)

//go:embed build/fs-restrict.tar
var fsRestrictGadgetBytes []byte

//go:embed build/kmod-restrict.tar
var kmodRestrictGadgetBytes []byte

//go:embed build/ptrace-restrict.tar
var ptraceRestrictGadgetBytes []byte

// Version is the version of the gadgets to run.
// It is set at build time via -ldflags.
var Version = "latest"

const (
	fsRestrictGadgetImageRepo     = "ghcr.io/dorser/micromize/fs-restrict"
	kmodRestrictGadgetImageRepo   = "ghcr.io/dorser/micromize/kmod-restrict"
	ptraceRestrictGadgetImageRepo = "ghcr.io/dorser/micromize/ptrace-restrict"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("Received shutdown signal")
		cancel()
	}()

	runtimeManager, err := runtime.NewManager()
	if err != nil {
		fmt.Printf("initializing runtime manager: %v", err)
		os.Exit(1)
	}

	defer runtimeManager.Close()

	ociHandlerOp := operators.NewOCIHandler()
	cliOp := operators.NewCLIOperator()

	localManagerOp, err := operators.NewLocalManager()
	if err != nil {
		fmt.Printf("creating local manager operator: %v", err)
		os.Exit(1)
	}

	contextManager := gadget.NewContextManager([]operators.DataOperator{ociHandlerOp, localManagerOp, cliOp})

	// Create gadget registry
	registry := gadget.NewRegistry(contextManager, runtimeManager)

	commonParams := map[string]string{
		"operator.cli.output": "json",
	}

	registry.Register("fs-restrict", &gadget.GadgetConfig{
		Bytes:     fsRestrictGadgetBytes,
		ImageName: fmt.Sprintf("%s:%s", fsRestrictGadgetImageRepo, Version),
		Params:    commonParams,
	})

	registry.Register("kmod-restrict", &gadget.GadgetConfig{
		Bytes:     kmodRestrictGadgetBytes,
		ImageName: fmt.Sprintf("%s:%s", kmodRestrictGadgetImageRepo, Version),
		Params:    commonParams,
	})

	registry.Register("ptrace-restrict", &gadget.GadgetConfig{
		Bytes:     ptraceRestrictGadgetBytes,
		ImageName: fmt.Sprintf("%s:%s", ptraceRestrictGadgetImageRepo, Version),
		Params:    commonParams,
	})

	// Run all gadgets
	if err := registry.RunAll(ctx); err != nil {
		fmt.Printf("running gadgets: %v", err)
		os.Exit(1)
	}

	// Wait for context to be done (which happens on signal)
	<-ctx.Done()
}
