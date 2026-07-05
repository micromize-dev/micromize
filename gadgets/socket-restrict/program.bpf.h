// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include <gadget/common.h>
#include <micromize/event_types.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef AF_AX25
#define AF_AX25 3
#endif

#ifndef AF_ATMPVC
#define AF_ATMPVC 8
#endif

#ifndef AF_X25
#define AF_X25 9
#endif

#ifndef AF_KEY
#define AF_KEY 15
#endif

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

#ifndef AF_ATMSVC
#define AF_ATMSVC 20
#endif

#ifndef AF_RDS
#define AF_RDS 21
#endif

#ifndef AF_CAN
#define AF_CAN 29
#endif

#ifndef AF_TIPC
#define AF_TIPC 30
#endif

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif

#ifndef AF_CAIF
#define AF_CAIF 37
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef AF_NFC
#define AF_NFC 39
#endif

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef AF_KCM
#define AF_KCM 41
#endif

#ifndef AF_SMC
#define AF_SMC 43
#endif

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

#ifndef NETLINK_AUDIT
#define NETLINK_AUDIT 9
#endif

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif

#define SOCKADDR_ALG_TYPE_OFFSET 2
#define SOCKADDR_ALG_TYPE_LEN 14
#define SOCKADDR_ALG_TYPE_END (SOCKADDR_ALG_TYPE_OFFSET + SOCKADDR_ALG_TYPE_LEN)

#define SOCKADDR_ALG_NAME_OFFSET 24
#define SOCKADDR_ALG_NAME_LEN 64
#define SOCKADDR_ALG_MIN_LEN (SOCKADDR_ALG_NAME_OFFSET + SOCKADDR_ALG_NAME_LEN)

#define EVENT_ALG_TYPE_LEN (SOCKADDR_ALG_TYPE_LEN + 1)

#define MAX_DENIED_FAMILIES 64
#define MAX_DENIED_NETLINK_PROTOCOLS 32

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process process;
  __u32 event_type;
  __u32 family;
  __u32 protocol;
  char alg_type[EVENT_ALG_TYPE_LEN];
  char alg_name[SOCKADDR_ALG_NAME_LEN];
};
