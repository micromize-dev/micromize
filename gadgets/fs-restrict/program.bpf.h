// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 micromize-Authors */

#include <gadget/common.h>
#include <gadget/filesystem.h>

#ifndef EPERM
#define EPERM 1
#endif

#ifndef FMODE_WRITE
#define FMODE_WRITE 0x2
#endif

struct event {
  gadget_timestamp timestamp_raw;
  struct gadget_process process;
  char filename[GADGET_PATH_MAX];
};
