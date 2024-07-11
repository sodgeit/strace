/*
 * Copyright (c) 2024 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef STRACE_EXECHOOHS_H
# define STRACE_EXECHOOKS_H

#include "defs.h"

void add_exec_hook(char *exec);
void add_param_to_current_exec_hook(char *param);
void init_exec_hooks(void);
void cleanup_exec_hooks(void);

// exec-hooks
void clone_returnval_exec_hook(kernel_long_t pid);
void execve_exec_hook(struct tcb *tcp, const unsigned int index);

#endif /* !STRACE_EXECHOOKS_H */
