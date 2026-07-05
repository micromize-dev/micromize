// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

const volatile int enforce = 1;
GADGET_PARAM(enforce);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(socket_restrict, events, event);

// Runtime-populated deny-list of address families, populated from userspace
// at gadget init from the --socket-deny-families flag. Empty by default means
// the configurable layer is a no-op; the hardcoded AF_ALG/AF_KEY/XFRM blocks
// below always apply regardless of this map.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_DENIED_FAMILIES);
  __type(key, __u16);
  __type(value, __u8);
} denied_families SEC(".maps");

// Runtime-populated deny-list of AF_NETLINK protocols, from
// --socket-deny-netlink-protocols. Empty by default.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_DENIED_NETLINK_PROTOCOLS);
  __type(key, __u32);
  __type(value, __u8);
} denied_netlink_protocols SEC(".maps");

static __always_inline bool is_family_denied(__u16 family) {
  return bpf_map_lookup_elem(&denied_families, &family) != NULL;
}

static __always_inline bool is_netlink_protocol_denied(__u32 protocol) {
  return bpf_map_lookup_elem(&denied_netlink_protocols, &protocol) != NULL;
}

// Block dangerous socket families at creation — the main choke point.
//
// Two layers:
//   1. Hardcoded, always-on blocks for the families with active kernel LPEs:
//        - AF_ALG          kernel crypto userspace API (CVE-2026-31431)
//        - AF_KEY          PF_KEY IPsec key management
//        - AF_NETLINK/XFRM XFRM/IPsec state & policy configuration
//      AF_KEY and NETLINK_XFRM are the entry point for the DirtyClone
//      killchain (CVE-2026-43503), a kernel LPE on the XFRM/ESP path.
//   2. A configurable deny-list layer (denied_families /
//      denied_netlink_protocols maps) for additional families that have no
//      legitimate cloud-native use. These emit the generic
//      EVENT_TYPE_SOCKET_FAMILY_DENIED_* events.
SEC("lsm/socket_create")
int BPF_PROG(micromize_socket_create, int family, int type, int protocol,
             int kern, int ret) {
  (void)type;

  // Preserve a deny decision from a previously-run LSM program in the chain.
  if (ret)
    return ret;

  if (kern)
    return 0;

  if (gadget_should_discard_data_current())
    return 0;

  __u16 fam = (__u16)family;
  __u32 socket_protocol = protocol >= 0 ? (__u32)protocol : 0;

  __u32 event_type;
  if (fam == AF_ALG) {
    event_type = EVENT_TYPE_SOCKET_AF_ALG_CREATE;
  } else if (fam == AF_KEY) {
    event_type = EVENT_TYPE_SOCKET_AF_KEY_CREATE;
  } else if (fam == AF_NETLINK && socket_protocol == NETLINK_XFRM) {
    event_type = EVENT_TYPE_SOCKET_XFRM_NETLINK_CREATE;
  } else if (is_family_denied(fam)) {
    event_type = EVENT_TYPE_SOCKET_FAMILY_DENIED_CREATE;
  } else if (fam == AF_NETLINK && is_netlink_protocol_denied(socket_protocol)) {
    event_type = EVENT_TYPE_SOCKET_FAMILY_DENIED_CREATE;
  } else {
    return 0;
  }

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event) {
    if (enforce)
      return -EPERM;
    return 0;
  }

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->event_type = event_type;
  event->family = (__u32)fam;
  event->protocol = socket_protocol;
  event->alg_type[0] = '\0';
  event->alg_name[0] = '\0';

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

// Defense-in-depth: block denied socket binds if a socket FD exists from
// before policy load. Preserves AF_ALG alg_type/alg_name for visibility.
SEC("lsm/socket_bind")
int BPF_PROG(micromize_socket_bind, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret) {
  // Preserve a deny decision from a previously-run LSM program in the chain.
  if (ret)
    return ret;

  if (gadget_should_discard_data_current())
    return 0;

  if (!address || addrlen < sizeof(__u16))
    return 0;

  __u16 family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), address);

  __u32 protocol = 0;
  __u32 event_type;
  if (family == AF_ALG) {
    event_type = EVENT_TYPE_SOCKET_AF_ALG_BIND;
  } else if (is_family_denied(family)) {
    event_type = EVENT_TYPE_SOCKET_FAMILY_DENIED_BIND;
  } else if (family == AF_NETLINK) {
    // Micro-optimization: only read sk_protocol for AF_NETLINK, and only
    // when the family itself was not already denied above.
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (sk)
      protocol = (__u32)BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
    if (!is_netlink_protocol_denied(protocol))
      return 0;
    event_type = EVENT_TYPE_SOCKET_FAMILY_DENIED_BIND;
  } else {
    return 0;
  }

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event) {
    if (enforce)
      return -EPERM;
    return 0;
  }

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->event_type = event_type;
  event->family = family;
  event->protocol = protocol;
  event->alg_type[0] = '\0';
  event->alg_name[0] = '\0';

  if (family == AF_ALG && addrlen >= SOCKADDR_ALG_TYPE_END) {
    bpf_probe_read_kernel(event->alg_type, SOCKADDR_ALG_TYPE_LEN,
                          (const char *)address + SOCKADDR_ALG_TYPE_OFFSET);
    event->alg_type[SOCKADDR_ALG_TYPE_LEN] = '\0';

    if (addrlen >= SOCKADDR_ALG_MIN_LEN) {
      bpf_probe_read_kernel(event->alg_name, SOCKADDR_ALG_NAME_LEN,
                            (const char *)address + SOCKADDR_ALG_NAME_OFFSET);
      event->alg_name[SOCKADDR_ALG_NAME_LEN - 1] = '\0';
    }
  }

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
