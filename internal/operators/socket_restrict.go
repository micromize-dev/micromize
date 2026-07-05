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
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// Linux socket address-family constants relevant to the socket-restrict
// gadget. Mirrors gadgets/socket-restrict/program.bpf.h.
var socketFamilyByName = map[string]uint16{
	"AF_UNIX":       1,
	"AF_INET":       2,
	"AF_AX25":       3,
	"AF_IPX":        4,
	"AF_APPLETALK":  5,
	"AF_NETROM":     6,
	"AF_BRIDGE":     7,
	"AF_ATMPVC":     8,
	"AF_X25":        9,
	"AF_INET6":      10,
	"AF_ROSE":       11,
	"AF_DECNET":     12,
	"AF_NETBEUI":    13,
	"AF_SECURITY":   14,
	"AF_KEY":        15,
	"AF_NETLINK":    16,
	"AF_PACKET":     17,
	"AF_ASH":        18,
	"AF_ECONET":     19,
	"AF_ATMSVC":     20,
	"AF_RDS":        21,
	"AF_IRDA":       23,
	"AF_PPPOX":      24,
	"AF_WANPIPE":    25,
	"AF_LLC":        26,
	"AF_IB":         27,
	"AF_MPLS":       28,
	"AF_CAN":        29,
	"AF_TIPC":       30,
	"AF_BLUETOOTH":  31,
	"AF_IUCV":       32,
	"AF_RXRPC":      33,
	"AF_ISDN":       34,
	"AF_PHONET":     35,
	"AF_IEEE802154": 36,
	"AF_CAIF":       37,
	"AF_ALG":        38,
	"AF_NFC":        39,
	"AF_VSOCK":      40,
	"AF_KCM":        41,
	"AF_QIPCRTR":    42,
	"AF_SMC":        43,
	"AF_XDP":        44,
}

// Linux AF_NETLINK protocol numbers consulted by socket-restrict.
var netlinkProtocolByName = map[string]uint32{
	"NETLINK_ROUTE":          0,
	"NETLINK_UNUSED":         1,
	"NETLINK_USERSOCK":       2,
	"NETLINK_FIREWALL":       3,
	"NETLINK_SOCK_DIAG":      4,
	"NETLINK_NFLOG":          5,
	"NETLINK_XFRM":           6,
	"NETLINK_SELINUX":        7,
	"NETLINK_ISCSI":          8,
	"NETLINK_AUDIT":          9,
	"NETLINK_FIB_LOOKUP":     10,
	"NETLINK_CONNECTOR":      11,
	"NETLINK_NETFILTER":      12,
	"NETLINK_IP6_FW":         13,
	"NETLINK_DNRTMSG":        14,
	"NETLINK_KOBJECT_UEVENT": 15,
	"NETLINK_GENERIC":        16,
	"NETLINK_SCSITRANSPORT":  18,
	"NETLINK_ECRYPTFS":       19,
	"NETLINK_RDMA":           20,
	"NETLINK_CRYPTO":         21,
}

// ParseSocketDenyFamilies parses a comma-separated string of address-family
// names (e.g. "AF_ALG,AF_TIPC") or decimal numbers (e.g. "38,30") into a
// deduplicated slice of family numbers. Empty entries are skipped. Whitespace
// is trimmed. Returns an error on unknown names or out-of-range numbers.
func ParseSocketDenyFamilies(input string) ([]uint16, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	seen := make(map[uint16]struct{})
	var out []uint16
	for _, raw := range strings.Split(input, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		var fam uint16
		if v, ok := socketFamilyByName[strings.ToUpper(token)]; ok {
			fam = v
		} else {
			n, err := strconv.ParseUint(token, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("unknown address family %q", token)
			}
			fam = uint16(n)
		}
		if _, dup := seen[fam]; dup {
			continue
		}
		seen[fam] = struct{}{}
		out = append(out, fam)
	}
	if len(out) > maxDeniedFamilies {
		return nil, fmt.Errorf("too many denied socket families: %d exceeds the BPF map capacity of %d", len(out), maxDeniedFamilies)
	}
	return out, nil
}

// ParseSocketDenyNetlinkProtocols parses a comma-separated string of
// AF_NETLINK protocol names (e.g. "NETLINK_NETFILTER,NETLINK_XFRM") or
// decimal numbers into a deduplicated slice of protocol numbers.
func ParseSocketDenyNetlinkProtocols(input string) ([]uint32, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil
	}
	seen := make(map[uint32]struct{})
	var out []uint32
	for _, raw := range strings.Split(input, ",") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		var proto uint32
		if v, ok := netlinkProtocolByName[strings.ToUpper(token)]; ok {
			proto = v
		} else {
			n, err := strconv.ParseUint(token, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("unknown netlink protocol %q", token)
			}
			proto = uint32(n)
		}
		if _, dup := seen[proto]; dup {
			continue
		}
		seen[proto] = struct{}{}
		out = append(out, proto)
	}
	if len(out) > maxDeniedNetlinkProtocols {
		return nil, fmt.Errorf("too many denied netlink protocols: %d exceeds the BPF map capacity of %d", len(out), maxDeniedNetlinkProtocols)
	}
	return out, nil
}

// Keep in sync with gadgets/socket-restrict/program.bpf.c.
const (
	socketDeniedFamiliesMapName         = "map/denied_families"
	socketDeniedNetlinkProtocolsMapName = "map/denied_netlink_protocols"
)

// BPF deny-list map capacities. Keep in sync with MAX_DENIED_FAMILIES and
// MAX_DENIED_NETLINK_PROTOCOLS in gadgets/socket-restrict/program.bpf.h.
const (
	maxDeniedFamilies         = 64
	maxDeniedNetlinkProtocols = 32
)

// NewSocketRestrictOperator returns a data operator that, on each gadget's
// init, populates the socket-restrict BPF deny-list maps from the supplied
// family / netlink-protocol slices. The operator is a no-op for any gadget
// that does not expose those maps.
func NewSocketRestrictOperator(families []uint16, netlinkProtocols []uint32) igoperators.DataOperator {
	slog.Debug("Creating socket-restrict operator",
		"families", families, "netlinkProtocols", netlinkProtocols)
	return simple.New("socketRestrictOperator",
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			if err := populateUint16Map(gadgetCtx, socketDeniedFamiliesMapName, families); err != nil {
				return fmt.Errorf("populating %s: %w", socketDeniedFamiliesMapName, err)
			}
			if err := populateUint32Map(gadgetCtx, socketDeniedNetlinkProtocolsMapName, netlinkProtocols); err != nil {
				return fmt.Errorf("populating %s: %w", socketDeniedNetlinkProtocolsMapName, err)
			}
			return nil
		}),
	)
}

func populateUint16Map(gadgetCtx igoperators.GadgetContext, name string, keys []uint16) error {
	m, ok := lookupMap(gadgetCtx, name)
	if !ok {
		return nil
	}
	value := uint8(1)
	for _, k := range keys {
		key := k
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("inserting key %d: %w", k, err)
		}
	}
	slog.Debug("Populated socket-restrict map", "name", name, "entries", len(keys))
	return nil
}

func populateUint32Map(gadgetCtx igoperators.GadgetContext, name string, keys []uint32) error {
	m, ok := lookupMap(gadgetCtx, name)
	if !ok {
		return nil
	}
	value := uint8(1)
	for _, k := range keys {
		key := k
		if err := m.Put(key, value); err != nil {
			return fmt.Errorf("inserting key %d: %w", k, err)
		}
	}
	slog.Debug("Populated socket-restrict map", "name", name, "entries", len(keys))
	return nil
}

func lookupMap(gadgetCtx igoperators.GadgetContext, name string) (*ebpf.Map, bool) {
	v, ok := gadgetCtx.GetVar(name)
	if !ok {
		return nil, false
	}
	m, ok := v.(*ebpf.Map)
	if !ok || m == nil {
		return nil, false
	}
	return m, true
}
