// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/filter.h>

static __always_inline bool
is_file_in_container_rootfs(struct task_struct *task, struct file *file) {
  struct vfsmount *file_mnt, *root_mnt;

  // Get the mount of the file being executed
  file_mnt = BPF_CORE_READ(file, f_path.mnt);

  // Get the root mount of the current process (container root)
  root_mnt = BPF_CORE_READ(task, fs, root.mnt);

  if (file_mnt != root_mnt)
    return false;

  return true;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(micromize_bprm_creds_for_exec, struct linux_binprm *bprm) {
  struct task_struct *task;
  struct file *file;

  if (gadget_should_discard_data_current())
    return 0;

  task = bpf_get_current_task_btf();
  file = bprm->file;

  if (!is_file_in_container_rootfs(task, file))
    return -EPERM;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
