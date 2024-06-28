/*
 * Copyright (c) 2024 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "exec_hooks.h"

#include "config.h"

#include <limits.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * There are four different blocks the exec_hooks will receive:
 * They all contain at least an empty json
 * - api block:
 *  	- sent once to each exec_hook before tracing starts
 *  	- called with at least these parameters:
 *  		--api {"version": "<version of this api>", "syscalls": [<list of supported syscalls>]}
 * - start block:
 *  	- sent once to each exec_hook before tracing starts and after the api block
 *  	- called with at least these parameters:
 *  		--start {"pid": <pid of strace>, "call": "<path of the strace exec>", 
 * 						"version": "<version of strace>", 
 * 						"current_directory": "<the directory where strace is called from>"
 * 						"argv": ["<arguments strace is called with>"]}
 * - callback block:
 *  	- sent to each exec_hook for each syscall
 *  	- called with at least these parameters:
 *  		--callback <json with data from the syscall>
 *  			-> for the returnvalue of clone the following json data will be sent:
 *  				{"syscall": "clone", "pid": <pid returned by clone>, 
 *  					"ppid": <the parent pid to the to the pid returned by clone>}
 *  			-> for the execve syscall the following json data will be sent:
 *  				{"syscall": "execve", "pids": <pid of the calling process of the execve>, 
 *  					"ppid": <the parent pid to the process calling execve>, 
 *  					"exec_path": "<the execpath used in execve>", 
 *  					"current_directory": "<the current directory of the process calling execve>", 
 *  					"argv": ["<all arguments present in execve>"]}
 *  			-> other syscalls and returnvalues not implemented
 * - end block:
 *  	- sent once to each exec_hook after tracing ended
 *  	- called with at least these parameters:
 *  		--end {}
 *
 * Additionally to the parameters mentioned above own options can be passed to the exec_hooks by using the 
 * '--exec-hook-param' option of strace. 
 */

enum callback_type {
	CALLBACK_API = 0,
	CALLBACK_START,
	CALLBACK_SYSCALL,
	CALLBACK_END,
};

enum syscall_type {
	SYSCALL_EXECVE = 0,
	SYSCALL_CLONE,
};

struct exec_hook_param {
	struct exec_hook_param *next;
	char *param;
};

struct exec_hook {
	struct exec_hook *next;
	char exec_path[PATH_MAX];
	int number_of_params;
	struct exec_hook_param *params;
};

struct syscall_info {
	enum syscall_type type;
	pid_t pid;
	pid_t ppid;
};

struct execve_info {
	struct syscall_info syscall;
	char exec_path[PATH_MAX];
	char current_directory[PATH_MAX];
	int argv_length;
	char **argv;
};

void remove_exec_hooks(void);
void remove_all_params_from_exec_hooks(void);

pid_t get_ppid(pid_t pid);
int get_current_directory(pid_t pid, char *current_directory, int result_size);
int get_string(struct tcb *tcp, const kernel_ulong_t addr, char *buffer, int buff_size);
char** get_argv(struct tcb *tcp, kernel_ulong_t addr, int *length);

int build_start_json(char *buffer[], int *offset, int *buffer_size, char *argv[], int argc);
int append_to_buffer_data_escaped(char **buffer, int *current_offset, int *buffer_size, const char *data);
int append_to_buffer(char **buffer, int *current_offset, int *buffer_size, const char *data);
int append_int_to_json(char **buffer, int *current_offset, int *buffer_size, const char *field_name, int data);
int append_string_to_json(char **buffer, int *current_offset, int *buffer_size, const char *field_name, const char *data);
int append_string_array_to_json(char **buffer, int *current_offset, int *buffer_size, const char *field_name, char **data, int data_length);
const char* get_syscall_name(enum syscall_type syscall);
const char* get_callback_type_option(enum callback_type syscall);
int append_execve_info_to_json(struct execve_info *syscall_info, char **buffer, int *current_offset, int *buffer_size);
int append_additional_syscall_info_to_json(struct syscall_info *syscall_info, char **buffer, int *current_offset, int *buffer_size);
char* build_json(struct syscall_info *syscall_info);
void send_data_to_exec_hooks(enum callback_type type, char *data);
void call_exec_hooks(struct syscall_info *info);

static const char* callback_options[] = {
	[CALLBACK_API] = "--api",
	[CALLBACK_START] = "--start",
	[CALLBACK_SYSCALL] = "--callback",
	[CALLBACK_END] = "--end"
};

struct exec_hook *active_exec_hooks = NULL;

static const char api_version[] = "1.0.0";

void add_exec_hook(char *exec) {
	struct exec_hook *new_exec_hook = malloc(sizeof(struct exec_hook));
	if (new_exec_hook == NULL) {
		exit(1);
	}

	if (realpath(exec, new_exec_hook->exec_path) == NULL) {
		exit(1);
	}
	new_exec_hook->next = NULL;
	new_exec_hook->number_of_params = 0;
	new_exec_hook->params = NULL;

	if (active_exec_hooks == NULL) {
		active_exec_hooks = new_exec_hook;
		return;
	}

	struct exec_hook *insert_pos = active_exec_hooks;
	while (insert_pos->next != NULL) {
		insert_pos = insert_pos->next;
	}
	insert_pos->next = new_exec_hook;
}

void add_param_to_current_exec_hook(char *param) {
	if (active_exec_hooks == NULL) {
		fprintf(stderr, "Can't add a parameter, when no hook has been added. Ignoring parameter...");
		return;
	}

	struct exec_hook_param *new_exec_hook_param = malloc(sizeof(struct exec_hook_param));

	if (new_exec_hook_param == NULL) {
		exit(1);
	}

	new_exec_hook_param->next = NULL;
	new_exec_hook_param->param = param;

	// get last added hook
	struct exec_hook *current_hook = active_exec_hooks;
	while (current_hook->next != NULL) {
		current_hook = current_hook->next;
	}

	// insert parameter into parameter linked list
	if (current_hook->params == NULL) {
		current_hook->params = new_exec_hook_param;
	} else {
		struct exec_hook_param *insert_pos = current_hook->params;

		while (insert_pos->next != NULL) {
			insert_pos = insert_pos->next;
		}

		insert_pos->next = new_exec_hook_param;
	}

	current_hook->number_of_params++;
}

void remove_exec_hooks(void) {
	struct exec_hook *current_exec_hook = active_exec_hooks;

	while (current_exec_hook != NULL) {
		struct exec_hook *delete_hook = current_exec_hook;
		current_exec_hook = current_exec_hook->next;
		free(delete_hook);
	}
}

void remove_all_params_from_exec_hooks(void) {
	struct exec_hook *current_exec_hook = active_exec_hooks;

	while (current_exec_hook != NULL) {
		struct exec_hook_param *current_param = current_exec_hook->params;
		while (current_param != NULL) {
			struct exec_hook_param *delete_param = current_param;
			current_param = current_param->next;
			free(delete_param);
		}
		current_exec_hook = current_exec_hook->next;
	}
}

void send_data_to_exec_hooks(enum callback_type type, char *data) {
	const char *callback_option = get_callback_type_option(type);

	if (callback_option == NULL) {
		return;
	}

	char option[100];
	strcpy(option, callback_option);

	struct exec_hook *current_hook = active_exec_hooks;

	while (current_hook != NULL) {
		pid_t pid = fork();

		if (pid < 0) {
			return;
		}

		if (pid == 0) {
			// the four fixed arguments are:
			// - exec path
			// - callback option
			// - data of the callback
			// - ending NULL
			int number_of_arguments = 4 + current_hook->number_of_params;
			char **arguments = malloc(number_of_arguments * sizeof(char*));

			int i = 0;
			struct exec_hook_param *current_param = current_hook->params;
			
			arguments[i++] = current_hook->exec_path;
			while (current_param != NULL) {
				arguments[i++] = current_param->param;
				current_param = current_param->next;
			}
			arguments[i++] = option;
			arguments[i++] = data;
			arguments[i++] = NULL;

			execve(current_hook->exec_path, arguments, NULL);
			// execve() does not return on success 
			// -> terminate child process when execve() fails
			free(arguments);
			exit(1);
		}

		waitpid(pid, NULL, 0);

		current_hook = current_hook->next;
	}
}

/**
 * Returns the written bytes (including the '\0') on success, else 0
 */
int append_to_buffer_data_escaped(char *buffer[], int *current_offset, int *buffer_size, const char *data) {
	const char *read_ptr = data;
	char *write_ptr = *buffer + *current_offset * sizeof(char);
	int prev_offset = *current_offset;

	while (*read_ptr != '\0') {
		// make sure the buffer is large enough to hold at the biggest 
		// escape sequence ('\uXXXX' -> 6 chars) and the ending '\0'
		if (*current_offset + 7 >= *buffer_size) {
			int new_buffer_size = *buffer_size * 2;
			char *new_buffer = realloc(*buffer, new_buffer_size * sizeof(char));
			if (new_buffer == NULL) {
				return 0;
			}
			*buffer = new_buffer;
			*buffer_size = new_buffer_size;
			write_ptr = *buffer + *current_offset * sizeof(char);
		}

		switch (*read_ptr) {
			case '\n':
				*write_ptr++ = '\\';
				*write_ptr++ = 'n';
				*current_offset += 2;
				break;
			case '\\':
				*write_ptr++ = '\\';
				*write_ptr++ = '\\';
				*current_offset += 2;
				break;
			case '\t':
				*write_ptr++ = '\\';
				*write_ptr++ = 't';
				*current_offset += 2;
				break;
			case '\r':
				*write_ptr++ = '\\';
				*write_ptr++ = 'r';
				*current_offset += 2;
				break;
			case '\f':
				*write_ptr++ = '\\';
				*write_ptr++ = 'f';
				*current_offset += 2;
				break;
			case '\"':
				*write_ptr++ = '\\';
				*write_ptr++ = '"';
				*current_offset += 2;
				break;
			 case '\b':
				*write_ptr++ = '\\';
				*write_ptr++ = 'b';
				*current_offset += 2;
				break;
			default:
				if ((*read_ptr >= ' ') && (*read_ptr < 0x7f)) {
					*write_ptr++ = *read_ptr;
					*current_offset += 1;
					break;
				}
				// write other characters as \uXXXX to the json
				int written_chars = sprintf(write_ptr, "\\u%04x", *read_ptr);
				if (written_chars == 6) {
					write_ptr += written_chars;
					*current_offset += written_chars;
				}
		}
		read_ptr++;
	}
	*write_ptr++ = '\0';
	return *current_offset - prev_offset + 1;
}

/**
 * Returns the written bytes in success, else 0
 */
int append_to_buffer(char **buffer, int *current_offset, int *buffer_size, const char *data) {
	int data_size = strlen(data);

	if (data_size + *current_offset + 1 >= *buffer_size) {
		int new_buffer_size = *buffer_size * 2;
		char *new_buffer = realloc(*buffer, new_buffer_size * sizeof(char));
		if (new_buffer == NULL) {
			return 0;
		}
		*buffer = new_buffer;
		*buffer_size = new_buffer_size;
	}
	
	int written_bytes = sprintf(&((*buffer)[*current_offset]), "%s", data);
	if (written_bytes < 0) {
		return 0;
	}
	*current_offset += written_bytes;
	return written_bytes + 1;
}

int append_string_to_json(char **buffer, int *current_offset, int *buffer_size, const char *field_name, const char *string) {
	int prev_offset = *current_offset;
	if (!append_to_buffer(buffer, current_offset, buffer_size, ",\"")) {
		return 0;
	}
	if (!append_to_buffer(buffer, current_offset, buffer_size, field_name)) {
		return 0;
	}
	if (!append_to_buffer(buffer, current_offset, buffer_size, "\":\"")) {
		return 0;
	}
	if (!append_to_buffer_data_escaped(buffer, current_offset, buffer_size, string)) {
		return 0;
	}
	if (!append_to_buffer(buffer, current_offset, buffer_size, "\"")) {
		return 0;
	}
	return *current_offset - prev_offset + 1;
}

int append_string_array_to_json(char **buffer, int *current_offset, int *buffer_size, const char *field_name, char **data, int data_length) {
	int prev_offset = *current_offset;
	if (data_length < 0) {
		return 0;
	}

	if (!append_to_buffer(buffer, current_offset, buffer_size, ",\"")) {
		return 0;
	}
	if (!append_to_buffer(buffer, current_offset, buffer_size, field_name)) {
		return 0;
	}

	if (data_length == 0) {
		if (!append_to_buffer(buffer, current_offset, buffer_size, (data ? "\":[]" : "\":null"))) {
			return 0;
		}
		return *current_offset - prev_offset + 1;
	}

	if (!append_to_buffer(buffer, current_offset, buffer_size, "\":[\"")) {
		return 0;
	}

	if (!append_to_buffer_data_escaped(buffer, current_offset, buffer_size, data[0])) {
		return 0;
	}

	for (int i = 1; i < data_length; i++) {
		if (!append_to_buffer(buffer, current_offset, buffer_size, "\",\"")) {
			return 0;
		}

		if (!append_to_buffer_data_escaped(buffer, current_offset, buffer_size, data[i])) {
			return 0;
		}
	}

	if (!append_to_buffer(buffer, current_offset, buffer_size, "\"]")) {
		return 0;
	}
	return *current_offset - prev_offset + 1;
}

int build_start_json(char *buffer[], int *offset, int *buffer_size, char *argv[], int argc) {
	char strace_exec_path[PATH_MAX];
	int length = readlink("/proc/self/exe", strace_exec_path, PATH_MAX);
	if ( length < 0 || length == PATH_MAX) {
		return 0;
	}

	*offset = snprintf(*buffer, *buffer_size, "{\"pid\":%d", getpid());
	if (*offset < 0 || *offset >= *buffer_size) {
		return 0;
	}

	if (!append_string_to_json(buffer, offset, buffer_size, "call", strace_exec_path)) {
		return 0;
	}

	if (!append_string_to_json(buffer, offset, buffer_size, "version", PACKAGE_VERSION)) {
		return 0;
	}

	char strace_current_directory[PATH_MAX];
	get_current_directory(getpid(), strace_current_directory, PATH_MAX);
	if (!append_string_to_json(buffer, offset, buffer_size, "current_directory", strace_current_directory)) {
		return 0;
	}

	if (!append_string_array_to_json(buffer, offset, buffer_size, "argv", argv, argc)) {
		return 0;
	}

	if (!append_to_buffer(buffer, offset, buffer_size, "}")) {
		return 0;
	}

	return *offset + 1;
}

void init_exec_hooks(int argc, char *argv[]) {
	if (!active_exec_hooks) {
		return;
	}

	static char api_json[100];
	int written_api_length = snprintf(api_json, sizeof(api_json), "{\"version\":\"%s\",\"syscalls\":[\"execve\",\"clone\"]}", api_version);
	if (written_api_length < 0 || written_api_length >= (int)sizeof(api_json)) {
		return;
	}

	send_data_to_exec_hooks(CALLBACK_API, api_json);

	int start_json_size = PATH_MAX * 2;
	int start_json_offset = 0;
	char *start_json = malloc(start_json_size * sizeof(char));
	if (start_json == NULL) {
		return;
	}

	if (!build_start_json(&start_json, &start_json_offset, &start_json_size, argv, argc)) {
		free(start_json);
		return;
	}

	send_data_to_exec_hooks(CALLBACK_START, start_json);
	free(start_json);
}

void cleanup_exec_hooks(void) {
	if (!active_exec_hooks) {
		return;
	}
	
	static char cleanup_json[] = "{}";

	send_data_to_exec_hooks(CALLBACK_END, cleanup_json);

	remove_all_params_from_exec_hooks();
	remove_exec_hooks();
}

const char* get_syscall_name(enum syscall_type syscall) {
	switch (syscall) {
		case SYSCALL_EXECVE:
			return "execve";
		case SYSCALL_CLONE: 
			return "clone";
		default:
			return "unknown";
	}
}

const char* get_callback_type_option(enum callback_type type) {
	switch (type) {
		case CALLBACK_API:
		case CALLBACK_START:
		case CALLBACK_SYSCALL:
		case CALLBACK_END:
			return callback_options[type];
		default:
			return NULL;
	}
}

int append_execve_info_to_json(struct execve_info *syscall_info, char **buffer, int *current_offset, int *buffer_size) {
	if (!append_string_to_json(buffer, current_offset, buffer_size, "exec_path", syscall_info->exec_path)) {
		return -1;
	}
	if (!append_string_to_json(buffer, current_offset, buffer_size, "current_directory", syscall_info->current_directory)) {
		return -1;
	}
	if (!append_string_array_to_json(buffer, current_offset, buffer_size, "argv", syscall_info->argv, syscall_info->argv_length)) {
		return -1;
	}
	return 0;
}

int append_additional_syscall_info_to_json(struct syscall_info *syscall_info, char **buffer, int *current_offset, int *buffer_size) {
	switch (syscall_info->type) {
		case SYSCALL_EXECVE:
			return append_execve_info_to_json((struct execve_info*)syscall_info, buffer, current_offset, buffer_size);
		default:
			return 0;
	}
}

/**
 * the json returned has to be freed
 */
char* build_json(struct syscall_info *syscall_info) {
	int buffer_size = PATH_MAX;
	int current_offset = 0;
	char *json_buffer = malloc(buffer_size * sizeof(char));

	if (json_buffer == NULL) {
		return NULL;
	}

	current_offset = snprintf(json_buffer, buffer_size, "{\"syscall\":\"%s\",\"pid\":%d,\"ppid\":%d", get_syscall_name(syscall_info->type), syscall_info->pid, syscall_info->ppid);
	if (current_offset < 0 || current_offset >= buffer_size) {
		free(json_buffer);
		return NULL;
	}

	int success = append_additional_syscall_info_to_json(syscall_info, &json_buffer, &current_offset, &buffer_size);

	if (success < 0) {
		free(json_buffer);
		return NULL;
	}

	if (!append_to_buffer(&json_buffer, &current_offset, &buffer_size, "}")) {
		free(json_buffer);
		return NULL;
	}

	return json_buffer;
}

void call_exec_hooks(struct syscall_info *syscall_info) {
	char *json = build_json(syscall_info);

	if (json == NULL) {
		return;
	}
	
	send_data_to_exec_hooks(CALLBACK_SYSCALL, json);

	free(json);
}

pid_t get_ppid(pid_t pid) {
	static const int path_size = 50;
	static const int buffer_size = 4096;

	int ppid;
	char process_information[buffer_size];
	char process_information_path[path_size];
	FILE *fp;

	if(sprintf(process_information_path, "/proc/%u/status", pid) < 0) {
		return -1;
	}
	
	fp = fopen(process_information_path, "r");
	if (fp != NULL) {
		size_t ret = fread(process_information, sizeof(char), buffer_size - 1, fp);
		if (!ret) {
			return -1;
		} else {
			process_information[ret++] = '\0';
		}
	}
	fclose(fp);
	char *ppid_loc = strstr(process_information, "\nPPid:");
	if (ppid_loc) {
		int ret = sscanf(ppid_loc, "\nPPid:%d", &ppid);
		if (!ret || ret == EOF) {
			return -1;
		}
		return ppid;
	} else {
		return -1;
	}
}

int get_current_directory(pid_t pid, char *current_directory, int result_size) {
	static const int buffer_size = 300;
	char buffer[buffer_size];

	if (!pid) {
		return 0;
	}

	if (sprintf(buffer, "/proc/%d/cwd", pid) < 0) {
		return 0;
	}

	ssize_t length = readlink(buffer, current_directory, result_size);
	if (length < 0 || length == result_size) {
		return 0;
	}

	current_directory[length] = '\0';
	return length;
}

int get_string(struct tcb *tcp, const kernel_ulong_t addr, char *buffer, int buff_size) {
	if (!tcp || !addr) {
		return -1;
	}

	if (!buffer || buff_size <= 0) {
		return -1;
	}

	return umovestr(tcp, addr, buff_size, buffer);
}

/**
 * the logic used here is mostly from the printargv(...) function in the file execve.c
 * 
 * the returned char** pointer and char* pointers inside have to be freed
 */
char** get_argv(struct tcb *tcp, kernel_ulong_t addr, int *length) {
	if (!addr) {
		*length = 0;
		return NULL;
	}

	if (!tcp || !length) {
		goto exit_error;
	}

	char **argv;
	int capacity = 4;

	argv = malloc(sizeof(char*) * capacity);

	if (argv == NULL) {
		goto exit_error;
	}

	const unsigned int wordsize = current_wordsize;
	kernel_ulong_t prev_addr = 0;
	unsigned int n = 0;
	*length = 0;

	for (;;prev_addr = addr, addr += wordsize, ++n) {
		union {
			unsigned int w32;
			kernel_ulong_t wl;
			char data[sizeof(kernel_ulong_t)];
		} cp;

		if (addr < prev_addr || umoven(tcp, addr, wordsize, cp.data)) {
			if (n == 0) {
				goto exit_error_free_argv;
			}
			break;
		}

		const kernel_ulong_t word = (wordsize == sizeof(cp.w32)) ? (kernel_ulong_t) cp.w32 : cp.wl;
		
		if (word == 0) {
			break;
		}

		char *argument = NULL;
		int argument_length = PATH_MAX;

		int result = 0;

		while (result == 0) {
			char *new_argument = realloc(argument, sizeof(char) * argument_length);

			if (new_argument == NULL) {
				if (argument) {
					free(argument);
				}
				goto exit_error_free_argv;
			}
			argument = new_argument;

			result = get_string(tcp, word, argument, argument_length);

			if (result < 0) {
				free(argument);
				goto exit_error_free_argv;
			}
			if (result > 0) {
				break;
			}

			argument_length *= 2;
		}

		if (*length + 1 > capacity) {
			capacity *= 2;
			char **new_argv = realloc(argv, sizeof(char*) * capacity);
			if (new_argv == NULL) {
				free(argument);
				goto exit_error_free_argv;
			}
			argv = new_argv;
		}

		argv[*length] = argument;
		*length += 1;
	}

	return argv;

exit_error_free_argv:
	for (int i = 0; i < *length; i++) {
		free(argv[i]);
	}
	free(argv);

exit_error:
	*length = -1;
	return NULL;
}

// exec-hooks
void clone_returnval_exec_hook(kernel_long_t pid) {
	if (!active_exec_hooks) {
		return;
	}

	struct syscall_info clone_info;
	clone_info.type = SYSCALL_CLONE;
	clone_info.pid = get_proc_pid(pid);
	clone_info.ppid = get_ppid(clone_info.pid);

	if (clone_info.ppid < 0) {
		return;
	}

	call_exec_hooks(&clone_info);
}

void execve_exec_hook(struct tcb *tcp, const unsigned int index) {
	if (!active_exec_hooks) {
		return;
	}

	if (!tcp->pid) {
		return;
	}

	struct execve_info syscall_info;
	syscall_info.syscall.type = SYSCALL_EXECVE;
	syscall_info.syscall.pid = get_proc_pid(tcp->pid);
	syscall_info.syscall.ppid = get_ppid(syscall_info.syscall.pid);
	int current_directory_length = get_current_directory(syscall_info.syscall.pid, syscall_info.current_directory, PATH_MAX);
	int success = get_string(tcp, tcp->u_arg[index], syscall_info.exec_path, sizeof(syscall_info.exec_path));
	syscall_info.argv = get_argv(tcp, tcp->u_arg[index + 1], &syscall_info.argv_length);

	if (current_directory_length == 0 || success < 0 || syscall_info.argv_length < 0 || syscall_info.syscall.ppid < 0) {
		return;
	}

	call_exec_hooks((struct syscall_info*)&syscall_info);

	for (int i = 0; i < syscall_info.argv_length; i++) {
		free(syscall_info.argv[i]);
	}
	free(syscall_info.argv);
}