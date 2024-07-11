/*
 * Copyright (c) 2024 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "exec_hooks.h"

void add_exec_hook(char* exec) {
	fprintf(stderr, "%s\n", __func__);
}

void add_param_to_current_exec_hook(char* param) {
	fprintf(stderr, "%s\n", __func__);
}

void init_exec_hooks(int argc, char *argv[]) {
	fprintf(stderr, "%s\n", __func__);
}

void cleanup_exec_hooks(void) {
	fprintf(stderr, "%s\n", __func__);
}

// exec-hooks

void clone_returnval_exec_hook(kernel_long_t pid) {
	fprintf(stderr, "%s\n", __func__);
}

void execve_exec_hook(struct tcb *tcp, const unsigned int index) {
	fprintf(stderr, "%s\n", __func__);
}