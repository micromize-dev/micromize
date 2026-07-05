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

package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/micromize-dev/micromize/internal/gadget"
	k8sclient "github.com/micromize-dev/micromize/internal/k8s"
	"github.com/micromize-dev/micromize/internal/logger"
	"github.com/micromize-dev/micromize/internal/operators"
	"github.com/micromize-dev/micromize/internal/runtime"
	"github.com/micromize-dev/micromize/internal/utils"
)

const (
	fsRestrictGadgetImageRepo     = "ghcr.io/micromize-dev/micromize/gadgets/fs-restrict"
	capRestrictGadgetImageRepo    = "ghcr.io/micromize-dev/micromize/gadgets/cap-restrict"
	ptraceRestrictGadgetImageRepo = "ghcr.io/micromize-dev/micromize/gadgets/ptrace-restrict"
	socketRestrictGadgetImageRepo = "ghcr.io/micromize-dev/micromize/gadgets/socket-restrict"
)

var (
	enforce                    bool
	verbose                    bool
	filterNamespaces           string
	filterImageDigest          string
	disableGadgets             string
	exemptLabel                string
	socketDenyFamilies         string
	socketDenyNetlinkProtocols string
)

// defaultSocketDenyFamilies is the conservative set of socket address
// families denied out of the box by the configurable layer of socket-restrict.
// It targets families that are essentially never used by cloud-native
// application containers but periodically ship kernel LPEs. AF_ALG, AF_KEY and
// AF_NETLINK/XFRM are always blocked by the gadget's hardcoded layer and are
// intentionally omitted here. AF_PACKET (MetalLB, keepalived, tcpdump-in-pod,
// kube-proxy IPVS, Cilium) and AF_VSOCK (firecracker/kata) are also excluded —
// operators that want them blocked can opt-in via --socket-deny-families.
const defaultSocketDenyFamilies = "AF_TIPC,AF_RDS,AF_SMC,AF_CAN,AF_NFC,AF_BLUETOOTH,AF_AX25,AF_ATMPVC,AF_ATMSVC,AF_X25,AF_KCM,AF_CAIF"

// defaultSocketDenyNetlinkProtocols is intentionally empty: blocking
// NETLINK_NETFILTER would break iptables-nft / nf_tables-based CNI plugins
// (Istio CNI, kube-proxy nft, etc.). NETLINK_XFRM is already blocked by the
// gadget's hardcoded layer. Operators concerned about nf_tables LPEs can
// opt-in via --socket-deny-netlink-protocols=NETLINK_NETFILTER.
const defaultSocketDenyNetlinkProtocols = ""

var rootCmd = &cobra.Command{
	Use:   "micromize",
	Short: "micromize is a security hardening tool for containerized applications",
	Long:  `micromize is a security hardening tool designed to detect and break the post-exploit kill chain for containerized applications using BPF LSM.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Setup(verbose)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = Version
	rootCmd.PersistentFlags().BoolVar(&enforce, "enforce", true, "Enforce restrictions")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&filterNamespaces, "filter-namespaces", "", "Comma-separated list of Kubernetes namespaces to monitor (empty means all except 'micromize'). Supports exclusion with '!' prefix.")
	rootCmd.PersistentFlags().StringVar(&filterImageDigest, "filter-image-digest", "", "Filter out containers running this image digest from monitoring (e.g. sha256:abc123...)")
	rootCmd.PersistentFlags().StringVar(&disableGadgets, "disable-gadgets", "", "Comma-separated list of gadgets to disable (e.g. ptrace-restrict,cap-restrict)")
	rootCmd.PersistentFlags().StringVar(&exemptLabel, "exempt-label", "micromize.dev/exempt", "Kubernetes label key used to mark namespaces as exempt from monitoring (value must be 'true'). Set to empty string to disable. Changes take effect on restart.")
	rootCmd.PersistentFlags().StringVar(&socketDenyFamilies, "socket-deny-families", defaultSocketDenyFamilies, "Comma-separated list of socket address families denied by socket-restrict's configurable layer. Names (e.g. AF_TIPC) or decimal numbers; case-insensitive. AF_ALG/AF_KEY/XFRM are always blocked regardless. Set to empty string to disable the configurable layer.")
	rootCmd.PersistentFlags().StringVar(&socketDenyNetlinkProtocols, "socket-deny-netlink-protocols", defaultSocketDenyNetlinkProtocols, "Comma-separated list of additional AF_NETLINK protocols denied by socket-restrict. Defaults to empty (NETLINK_XFRM is always blocked). Use NETLINK_NETFILTER to block nf_tables LPE chains (incompatible with iptables-nft / nf_tables-based CNI).")
}

func run(ctx context.Context) error {
	slog.Info("Starting micromize...")

	// Validate BPF LSM is enabled before starting
	if err := utils.ValidateBPFLSM(); err != nil {
		return fmt.Errorf("BPF LSM validation failed: %w", err)
	}
	slog.Info("BPF LSM is enabled")

	if enforce {
		slog.Info("Enforcement enabled")
	} else {
		slog.Info("Enforcement disabled (audit mode)")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("Received shutdown signal")
		cancel()
	}()

	runtimeManager, err := runtime.NewManager()
	if err != nil {
		return fmt.Errorf("initializing runtime manager: %w", err)
	}

	defer runtimeManager.Close()

	ociHandlerOp := operators.NewOCIHandler()
	eventTypeOp := operators.NewEventTypeOperator()
	outputOp := operators.NewOutputOperator()

	localManagerOp, err := operators.NewLocalManager()
	if err != nil {
		return fmt.Errorf("creating local manager operator: %w", err)
	}

	socketDenyFamilyList, err := operators.ParseSocketDenyFamilies(socketDenyFamilies)
	if err != nil {
		return fmt.Errorf("parsing --socket-deny-families: %w", err)
	}
	socketDenyNetlinkProtocolList, err := operators.ParseSocketDenyNetlinkProtocols(socketDenyNetlinkProtocols)
	if err != nil {
		return fmt.Errorf("parsing --socket-deny-netlink-protocols: %w", err)
	}
	slog.Info("Socket-restrict deny-list",
		"families", socketDenyFamilyList,
		"netlinkProtocols", socketDenyNetlinkProtocolList)
	socketRestrictOp := operators.NewSocketRestrictOperator(socketDenyFamilyList, socketDenyNetlinkProtocolList)

	contextManager := gadget.NewContextManager([]operators.DataOperator{ociHandlerOp, localManagerOp, socketRestrictOp, eventTypeOp, outputOp})

	// Create gadget registry
	registry := gadget.NewRegistry(contextManager, runtimeManager)

	hostPidnsID, err := utils.GetHostPidNamespaceID()
	if err != nil {
		return fmt.Errorf("getting host pid namespace ID: %w", err)
	}

	selfNamespace := k8sclient.CurrentNamespace("micromize")
	nsFilter := utils.BuildNamespaceFilter(filterNamespaces, selfNamespace)

	// Discover namespaces exempt by label and append them as exclusions.
	// Evaluated at startup only — a DaemonSet restart is required to pick up
	// changes to namespace labels.
	if exemptLabel != "" {
		k8s, err := k8sclient.NewClient()
		if err != nil {
			slog.Warn("Could not build Kubernetes client for exempt label discovery; skipping", "error", err)
		} else {
			exemptNS, err := k8sclient.ListExemptNamespaces(ctx, k8s, exemptLabel)
			if err != nil {
				slog.Warn("Could not list exempt namespaces; skipping", "label", exemptLabel, "error", err)
			} else if len(exemptNS) > 0 {
				slog.Info("Exempt namespaces discovered (startup only)", "namespaces", exemptNS, "label", exemptLabel)
				for _, ns := range exemptNS {
					nsFilter = utils.AppendNamespaceExclusion(nsFilter, ns)
				}
			}
		}
	}

	slog.Info("Namespace filter", "filter", nsFilter)

	disabled := buildDisabledSet(disableGadgets)
	if len(disabled) > 0 {
		slog.Info("Disabled gadgets", "gadgets", disableGadgets)
	}

	commonParams := map[string]string{
		"operator.oci.ebpf.enforce":           fmt.Sprintf("%d", utils.BoolToInt(enforce)),
		"operator.LocalManager.k8s-namespace": nsFilter,
	}

	if filterImageDigest != "" {
		digest := strings.TrimSpace(strings.TrimPrefix(filterImageDigest, "!"))
		if digest == "" {
			slog.Warn("Ignoring --filter-image-digest with an empty digest value", "value", filterImageDigest)
		} else {
			commonParams["operator.LocalManager.runtime-containerimage-digest"] = "!" + digest
			slog.Info("Filtering out containers by image digest", "digest", digest)
		}
	}

	if !disabled["fs-restrict"] {
		registry.Register("fs-restrict", &gadget.GadgetConfig{
			Bytes:     fsRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", fsRestrictGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	capRestrictParams := map[string]string{
		"operator.oci.ebpf.host_pidns_id": fmt.Sprintf("%d", hostPidnsID),
	}
	for k, v := range commonParams {
		capRestrictParams[k] = v
	}

	if !disabled["cap-restrict"] {
		registry.Register("cap-restrict", &gadget.GadgetConfig{
			Bytes:     capRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", capRestrictGadgetImageRepo, Version),
			Params:    capRestrictParams,
		})
	}

	if !disabled["ptrace-restrict"] {
		registry.Register("ptrace-restrict", &gadget.GadgetConfig{
			Bytes:     ptraceRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", ptraceRestrictGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	if !disabled["socket-restrict"] {
		registry.Register("socket-restrict", &gadget.GadgetConfig{
			Bytes:     socketRestrictGadgetBytes,
			ImageName: fmt.Sprintf("%s:%s", socketRestrictGadgetImageRepo, Version),
			Params:    commonParams,
		})
	}

	// Run all gadgets
	if err := registry.RunAll(ctx); err != nil {
		return fmt.Errorf("running gadgets: %w", err)
	}

	// Wait for context to be done (which happens on signal)
	<-ctx.Done()
	return nil
}

// buildDisabledSet parses a comma-separated list of gadget names into a set
// for O(1) lookup. Empty string returns an empty set.
func buildDisabledSet(disableGadgets string) map[string]bool {
	disabled := make(map[string]bool)
	if disableGadgets == "" {
		return disabled
	}
	for _, name := range strings.Split(disableGadgets, ",") {
		if n := strings.TrimSpace(name); n != "" {
			disabled[n] = true
		}
	}
	return disabled
}
