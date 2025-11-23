// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/filter.h>

SEC("lsm/kernel_load_data")
int BPF_PROG(micromize_kernel_load_data, enum kernel_load_data_id id,
             bool contents) {
  if (gadget_should_discard_data_current()) {
    return 0;
  }

  // Block kernel module loading
  if (id == LOADING_MODULE) {
    return -EPERM;
  }

  return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(micromize_kernel_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents) {
  if (gadget_should_discard_data_current())
    return 0;

  if (id == READING_MODULE) {
    return -EPERM;
  }

  return 0;
}

SEC("lsm/capable")
int BPF_PROG(micromize_capable, const struct cred *cred,
             struct user_namespace *ns, int cap, unsigned int opts) {
  if (gadget_should_discard_data_current())
    return 0;

  if (cap == CAP_SYS_MODULE) {
    bpf_printk("capable: blocking CAP_SYS_MODULE (loading/unloading)\n");
    return -EPERM;
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
