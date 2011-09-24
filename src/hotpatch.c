/*
 * hotpatch is a dll injection strategy.
 * Copyright (c) 2010-2011, Vikas Naresh Kumar, Selective Intellect LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Selective Intellect LLC nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <hotpatch_config.h>
#include <hotpatch_internal.h>
#include <hotpatch.h>

static int hotpatch_cmpqsort(const void *p1, const void *p2)
{
	return strcmp(*(char * const *)p1, * (char * const *)p2);
}

hotpatch_t *hotpatch_create(pid_t pid, int verbose)
{
	hotpatch_t *hp = NULL;
	if (pid > 0) {
		hp = malloc(sizeof(*hp));
		if (hp) {
			memset(hp, 0, sizeof(*hp));
			hp->verbose = verbose;
			hp->pid = pid;
			hp->is64 = HOTPATCH_EXE_IS_NEITHER;
			hp->fd_exe = exe_open_file(hp->pid, hp->verbose);
			if (hp->fd_exe < 0) {
				hotpatch_destroy(hp);
				return NULL;
			}
			if (exe_load_headers(hp) >= 0) {
				LOG_INFO_HEADERS_LOADED(verbose);
			}
			if (hp->symbols && hp->symbols_num > 0) {
				qsort(hp->symbols, hp->symbols_num,
					  sizeof(*hp->symbols), hotpatch_cmpqsort);
			}
		} else {
			LOG_ERROR_OUT_OF_MEMORY;
		}
	} else {
		LOG_ERROR_INVALID_PID(pid);
	}
	return hp;
}

void hotpatch_destroy(hotpatch_t *hp)
{
	if (hp) {
		if (hp->attached)
			hotpatch_detach(hp);
		if (hp->fd_exe > 0) {
			close(hp->fd_exe);
			hp->fd_exe = -1;
		}
		if (hp->symbols) {
			size_t idx;
			for (idx = 0; idx < hp->symbols_num; ++idx) {
				free(hp->symbols[idx].name);
				hp->symbols[idx].name = NULL;
			}
			free(hp->symbols);
		}
		hp->symbols = NULL;
		hp->symbols_num = 0;
		hp->strsectbl_size = 0;
		if (hp->strsectbl) {
			free(hp->strsectbl);
			hp->strsectbl = NULL;
		}
		if (hp->sechdrs) {
			free(hp->sechdrs);
			hp->sechdrs = NULL;
		}
		if (hp->interp) {
			free(hp->interp);
			hp->interp = NULL;
		}
		if (hp->proghdrs) {
			free(hp->proghdrs);
			hp->proghdrs = NULL;
		}
		free(hp);
		hp = NULL;
	}
}

uintptr_t hotpatch_read_symbol(hotpatch_t *hp, const char *symbol, int *type, size_t *sz)
{
	uintptr_t ptr = 0;
	size_t idx = 0;
	if (!hp || !symbol || !hp->symbols) {
		if (hp->verbose > 2)
			fprintf(stderr, "[%s:%d] Invalid arguments.\n", __func__, __LINE__);
		return (uintptr_t)0;
	}
	for (idx = 0; idx < hp->symbols_num; ++idx) {
		const char *name = hp->symbols[idx].name;
		if (strcmp(name, symbol) == 0) {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] Found %s in symbol list at %ld\n",
						__func__, __LINE__, symbol, idx);
			ptr = hp->symbols[idx].address;
			if (type)
				*type = hp->symbols[idx].type;
			if (sz)
				*sz = hp->symbols[idx].size;
			break;
		}
	}
	if (hp->verbose > 2)
		fprintf(stderr, "[%s:%d] Symbol %s has address 0x%lx\n", __func__,
				__LINE__, symbol, ptr);
	return ptr;
}

uintptr_t hotpatch_get_entry_point(hotpatch_t *hp)
{
	return hp ? hp->entry_point : 0;
}

int hotpatch_insert(hotpatch_t *hp, const char *dll, const char *symbol,
				void *arg)
{
	if (!hp) {
		return -1;
	}
	return 0;
}

size_t hotpatch_strnlen(const char *str, size_t maxlen)
{
    size_t len = 0;
    /* succinct code */
    if (str)
        while (len < maxlen && str[len++] != '\0');
    return len;
}

int hotpatch_attach(hotpatch_t *hp)
{
	if (!hp)
		return -1;
	if (!hp->attached) {
		hp->attached = false;
		if (hp->verbose > 3)
			fprintf(stderr, "[%s:%d] Trying to attach to PID %d\n", __func__,
					__LINE__, hp->pid);
		if (ptrace(PTRACE_ATTACH, hp->pid, NULL, NULL) < 0) {
			int err = errno;
			fprintf(stderr, "[%s:%d] Ptrace Attach failed with error %s\n",
					__func__, __LINE__, strerror(err));
		} else {
			int status = 0;
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] Waiting for the child.\n", __func__,
						__LINE__);
			if (waitpid(-1, &status, 0) < 0) {
				int err = errno;
				fprintf(stderr, "[%s:%d] Waitpid failed with error: %s\n",
						__func__, __LINE__, strerror(err));
			} else {
				if (WIFEXITED(status) || WIFSIGNALED(status)) {
					fprintf(stderr, "[%s:%d] PID %d was terminated.\n",
							__func__, __LINE__, hp->pid);
				} else {
					hp->attached = true;
					if (hp->verbose > 0)
						fprintf(stderr, "[%s:%d] Attached to PID %d\n",
								__func__, __LINE__, hp->pid);
				}
			}
		}
	}
	return hp->attached ? 0 : -1;
}

int hotpatch_detach(hotpatch_t *hp)
{
	int rc = -1;
	if (hp && hp->attached) {
		if (hp->verbose > 3)
			fprintf(stderr, "[%s:%d] Detaching from PID %d\n", __func__,
					__LINE__, hp->pid);
		if (ptrace(PTRACE_DETACH, hp->pid, NULL, NULL) < 0) {
			int err = errno;
			fprintf(stderr, "[%s:%d] Ptrace detach failed with error %s\n",
					__func__, __LINE__, strerror(err));
		} else {
			rc = 0;
			if (hp->verbose > 0)
				fprintf(stderr, "[%s:%d] Detached from PID %d\n", __func__,
						__LINE__, hp->pid);
		}
		hp->attached = false;
	}
	return rc;
}

int hotpatch_set_execution_pointer(hotpatch_t *hp, uintptr_t ptr)
{
	int rc = -1;
	if (ptr && hp && hp->attached) {
		struct user regs;
		memset(&regs, 0, sizeof(regs));
		if (ptrace(PTRACE_GETREGS, hp->pid, NULL, &regs) < 0) {
			int err = errno;
			fprintf(stderr, "[%s:%d] Ptrace getregs failed with error %s\n",
					__func__, __LINE__, strerror(err));
		} else {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] RIP is 0x%lx\n", __func__, __LINE__,
						regs.regs.rip);
			if (ptr == hp->entry_point)
				ptr += sizeof(void *);
			regs.regs.rip = ptr;
			if (ptrace(PTRACE_SETREGS, hp->pid, NULL, &regs) < 0) {
				int err = errno;
				fprintf(stderr, "[%s:%d] Ptrace setregs failed with error %s\n",
						__func__, __LINE__, strerror(err));
			} else {
				if (hp->verbose > 0)
					fprintf(stderr, "[%s:%d] Set RIP to 0x%lx\n", __func__, __LINE__,
							ptr);
				rc = 0;
			}
		}
	} else {
		if (!ptr) {
			fprintf(stderr, "[%s:%d] The execution pointer is null.\n",
					__func__, __LINE__);
		}
		if (!hp || !hp->attached) {
			fprintf(stderr, "[%s:%d] The process is not attached to.\n",
					__func__, __LINE__);
		}
	}
	return rc;
}

int hotpatch_inject_code_at(hotpatch_t *hp, uintptr_t location,
				const unsigned char *code, size_t len, int8_t execute)
{
	int rc = -1;
	if (location && hp && hp->attached && code && len > 0) {

	} else {
		if (!location) {
			fprintf(stderr, "[%s:%d] The location pointer is null.\n",
					__func__, __LINE__);
		}
		if (!hp || !hp->attached) {
			fprintf(stderr, "[%s:%d] The process is not attached to.\n",
					__func__, __LINE__);
		}
		if (!code || len == 0) {
			fprintf(stderr, "[%s:%d] No code specified for injection.\n",
					__func__, __LINE__);
		}
	}
	return rc;
}
