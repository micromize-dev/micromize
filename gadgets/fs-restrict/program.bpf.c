// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include "program.bpf.h"

#include <vmlinux.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filesystem.h>
#include <gadget/filter.h>
#include <gadget/macros.h>

const volatile bool enforce = true;
GADGET_PARAM(enforce);

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(fs_restrict, events, event);

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

SEC("lsm/file_open")
int BPF_PROG(micromize_file_open, struct file *file) {
  if (gadget_should_discard_data_current())
    return 0;

  if (!(file->f_mode & FMODE_WRITE))
    return 0;

  struct task_struct *task = bpf_get_current_task_btf();
  struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);

  // Allow host processes (like runc) to write to /proc.
  // We identify them by checking if their executable binary is outside the
  // container's rootfs. Normal container processes are bound to the container
  // rootfs.
  if (exe_file && !is_file_in_container_rootfs(task, exe_file))
    return 0;

  struct inode *inode = BPF_CORE_READ(file, f_inode);
  struct super_block *sb = BPF_CORE_READ(inode, i_sb);
  unsigned long magic = BPF_CORE_READ(sb, s_magic);

  if (magic == PROC_SUPER_MAGIC) {
    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
      return 0;

    gadget_process_populate(&event->process);
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    struct path f_path = BPF_CORE_READ(file, f_path);
    char *path_str = get_path_str(&f_path);
    if (path_str) {
      bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                                path_str);
    } else {
      event->filename[0] = '\0';
    }

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    if (enforce)
      return -EPERM;
  }

  return 0;
}

SEC("lsm/bprm_creds_for_exec")
int BPF_PROG(micromize_bprm_creds_for_exec, struct linux_binprm *bprm) {
  struct task_struct *task;
  struct file *file;

  if (gadget_should_discard_data_current())
    return 0;

  task = bpf_get_current_task_btf();
  file = bprm->file;

  if (!is_file_in_container_rootfs(task, file)) {
    struct event *event;
    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
      return 0;

    gadget_process_populate(&event->process);
    event->timestamp_raw = bpf_ktime_get_boot_ns();

    struct path f_path = BPF_CORE_READ(file, f_path);
    char *path_str = get_path_str(&f_path);
    if (path_str)
      bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                                path_str);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    if (enforce)
      return -EPERM;
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
