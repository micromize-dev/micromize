// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

const volatile int enforce = 1;
GADGET_PARAM(enforce);

const volatile __u64 host_pidns_id = 0;
GADGET_PARAM(host_pidns_id);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(cap_restrict, events, event);

static __always_inline int check_unshare_flags(unsigned long flags) {
  unsigned long ns_flags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS |
                           CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |
                           CLONE_NEWNET;
  return (flags & ns_flags);
}

static __always_inline __u64 get_current_pidns_id() {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[level].ns);
  return BPF_CORE_READ(ns, ns.inum);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int micromize_clone_enter(struct syscall_trace_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;

  unsigned long flags = ctx->args[0];
  if (!check_unshare_flags(flags))
    return 0;

  u64 pid = bpf_get_current_pid_tgid();
  struct cap_info info = {};
  info.flags = flags;
  info.syscall = SYSCALL_CLONE;
  bpf_map_update_elem(&catch_at_cap, &pid, &info, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int micromize_unshare_enter(struct syscall_trace_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;

  unsigned long flags = ctx->args[0];
  if (!check_unshare_flags(flags))
    return 0;

  u64 pid = bpf_get_current_pid_tgid();
  struct cap_info info = {};
  info.flags = flags;
  info.syscall = SYSCALL_UNSHARE;
  bpf_map_update_elem(&catch_at_cap, &pid, &info, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int micromize_setns_enter(struct syscall_trace_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;

  // allow setns from host pid namespace
  if (host_pidns_id != 0 && get_current_pidns_id() == host_pidns_id)
    return 0;

  u64 pid = bpf_get_current_pid_tgid();
  struct cap_info info = {};
  info.flags = ctx->args[1];
  info.syscall = SYSCALL_SETNS;
  bpf_map_update_elem(&catch_at_cap, &pid, &info, BPF_ANY);

  return 0;
}

SEC("lsm/capable")
int BPF_PROG(micromize_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts) {
  if (gadget_should_discard_data_current())
    return 0;

  if (cap != CAP_SYS_MODULE && cap != CAP_SYS_ADMIN)
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  if (cap == CAP_SYS_ADMIN) {
    u64 pid = bpf_get_current_pid_tgid();
    struct cap_info *info;

    info = bpf_map_lookup_elem(&catch_at_cap, &pid);
    bpf_map_delete_elem(&catch_at_cap, &pid);

    if (!info) {
      gadget_discard_buf(event);
      return 0;
    }

    event->flags = info->flags;
    event->syscall = info->syscall;
  }

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();
  event->cap = cap;

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
