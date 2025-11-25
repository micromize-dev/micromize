// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/buffer.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

const volatile int enforce = 1;
GADGET_PARAM(enforce);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(ptrace_restrict, events, event);

SEC("lsm/ptrace_access_check")
int BPF_PROG(micromize_ptrace_access_check, struct task_struct *child,
             unsigned int mode) {
  if (gadget_should_discard_data_current())
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(micromize_ptrace_traceme, struct task_struct *parent) {
  if (gadget_should_discard_data_current())
    return 0;

  struct event *event;
  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  gadget_process_populate(&event->process);
  event->timestamp_raw = bpf_ktime_get_boot_ns();

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  if (enforce)
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
