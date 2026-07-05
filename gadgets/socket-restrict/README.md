# socket-restrict

Restrict dangerous socket address families and protocols in containers.

The gadget enforces in two layers:

1. **Hardcoded, always-on blocks** for the families with active kernel LPEs.
   These are enforced regardless of configuration:
   - `AF_ALG` — kernel crypto userspace API. Motivated by CVE-2026-31431
     (Copy Fail), a privilege escalation in `algif_aead` reachable via
     `AF_ALG` sockets.
   - `AF_KEY` — PF_KEY IPsec key management.
   - `AF_NETLINK` with protocol `NETLINK_XFRM` — XFRM/IPsec state & policy
     configuration.

   `AF_KEY` and `NETLINK_XFRM` are the only ways to configure XFRM/IPsec from
   userspace and are the entry point for the DirtyClone killchain
   (CVE-2026-43503), a kernel LPE on the XFRM/ESP packet path. Blocking them
   at socket creation removes the attack surface before any vulnerable kernel
   code is reached.

2. **A configurable deny-list layer** for additional address families and
   `AF_NETLINK` protocols that have no legitimate cloud-native use. This layer
   is driven by two BPF maps populated at startup from CLI flags, so operators
   can tune coverage without rebuilding the BPF program.

## Configurable layer

| Flag | Default | Notes |
|---|---|---|
| `--socket-deny-families` | `AF_TIPC,AF_RDS,AF_SMC,AF_CAN,AF_NFC,AF_BLUETOOTH,AF_AX25,AF_ATMPVC,AF_ATMSVC,AF_X25,AF_KCM,AF_CAIF` | Additional families to deny. Names or decimal numbers, case-insensitive. `AF_ALG`/`AF_KEY`/XFRM are always blocked and need not be listed. |
| `--socket-deny-netlink-protocols` | *(empty)* | Additional `AF_NETLINK` protocols to deny. `NETLINK_XFRM` is always blocked. |

The defaults are **conservative**: only niche/legacy families with no
realistic cloud-native use are denied out of the box.

### Opt-in (compatibility-sensitive)

These are **not** denied by default because they have legitimate uses; enable
them explicitly after validating your workloads (ideally in audit mode,
`--enforce=false`, first):

| Item | Enable with | Breaks if in use |
|---|---|---|
| `AF_PACKET` | `--socket-deny-families=...,AF_PACKET` | MetalLB, keepalived, tcpdump-in-pod, kube-proxy IPVS, Cilium |
| `AF_VSOCK` | `--socket-deny-families=...,AF_VSOCK` | firecracker / kata-containers agents |
| `NETLINK_NETFILTER` | `--socket-deny-netlink-protocols=NETLINK_NETFILTER` | iptables-nft, kube-proxy nft mode, Istio CNI, nft-based CNIs |

## Recommended rollout (audit → enforce)

1. Deploy with `--enforce=false` and the default deny-lists. Watch for
   `socket_family_denied_create` / `_bind` events on a representative
   workload sample. Defaults should produce ~zero events on a normal data
   plane.
2. Opt-in additional families/protocols incrementally, still in audit mode,
   validating against your CNI / kube-proxy mode / service mesh / IPsec.
3. Switch to `--enforce=true` once the audit log is clean.

## Events

| Event | When |
|---|---|
| `af_alg_socket_create` / `af_alg_socket_bind` | `AF_ALG` (hardcoded) |
| `af_key_socket_create` | `AF_KEY` (hardcoded) |
| `xfrm_netlink_socket_create` | `AF_NETLINK`/`NETLINK_XFRM` (hardcoded) |
| `socket_family_denied_create` / `socket_family_denied_bind` | any family/protocol from the configurable deny-list |

## Hooks

| Hook | Purpose |
|---|---|
| `lsm/socket_create` | Block denied socket families and `AF_NETLINK` protocols at creation time (main choke point). |
| `lsm/socket_bind` | Defense-in-depth: block denied binds if a socket FD existed before policy load. Preserves `alg_type`/`alg_name` for `AF_ALG` visibility. |

Both hooks preserve a prior LSM program's deny decision via the `ret`
chaining argument, so socket-restrict never overrides another LSM's block.

## Getting Started

```bash
sudo ig run ghcr.io/micromize-dev/micromize/gadgets/socket-restrict:latest
```
