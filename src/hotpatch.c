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
#ifdef HOTPATCH_USE_ASM
	#include <call32.h>
	#include <call64.h>
#endif

#define LIB_LD "ld"
#define LIB_C "libc"
#define LIB_DL "libdl"
#define LIB_PTHREAD "libpthread"

static int hotpatch_gather_functions(hotpatch_t *hp)
{
	int verbose = 0;
	bool ld_found = false;
	bool c_found = false;
	bool dl_found = false;
	bool pthread_found = false;
	if (!hp || !hp->libs)
		return -1;
	verbose = hp->verbose;
	if (hp->ld_maps_num <= 0)
		return -1;
	memset(hp->libs, 0, sizeof(hp->libs));
#undef LD_PROCMAPS_FIND_LIB
#define LD_PROCMAPS_FIND_LIB(name,flag,index,retval) \
do { \
	if (verbose > 2) \
		fprintf(stderr, "[%s:%d] Checking if %s exists in procmaps.\n",\
			__func__, __LINE__, name);\
	if (ld_find_library(hp->ld_maps, hp->ld_maps_num, \
						name, flag, &hp->libs[index], verbose) < 0) { \
		if (verbose > 0) \
			fprintf(stderr, "[%s:%d] %s not mapped.\n", \
					__func__, __LINE__, name); \
		retval = false; \
	} else { \
		retval = true; \
		if (verbose > 2) \
			fprintf(stderr, "[%s:%d] Found %s\n", \
					__func__, __LINE__, name); \
	} \
} while (0)
#undef LD_LIB_FIND_FN_ADDR
#define LD_LIB_FIND_FN_ADDR(fn,outfn,index) \
do { \
	if (outfn) break; \
	outfn = ld_find_address(&hp->libs[HOTPATCH_##index], fn, verbose); \
	if (outfn != 0) { \
		if (verbose > 0) \
			fprintf(stderr, "[%s:%d] Found %s at 0x"LX" in %s\n", \
					__func__, __LINE__, fn, outfn, index); \
	} else { \
		if (verbose > 0) \
			fprintf(stderr, "[%s:%d] %s not found in %s.\n", \
					__func__, __LINE__, fn, index); \
	} \
} while (0)
	if (hp->exe_interp.name) {
		LD_PROCMAPS_FIND_LIB(hp->exe_interp.name, true, HOTPATCH_LIB_LD,
				ld_found);
	}
	if (!ld_found) {
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] No interpreter found. Guessing.\n",
					__func__, __LINE__);
		LD_PROCMAPS_FIND_LIB(LIB_LD, false, HOTPATCH_LIB_LD, ld_found);
	}
	LD_PROCMAPS_FIND_LIB(LIB_C, false, HOTPATCH_LIB_C, c_found);
	LD_PROCMAPS_FIND_LIB(LIB_DL, false, HOTPATCH_LIB_DL, dl_found);
	LD_PROCMAPS_FIND_LIB(LIB_PTHREAD, false, HOTPATCH_LIB_PTHREAD,
			pthread_found);
	if (c_found) {
		LD_LIB_FIND_FN_ADDR("malloc", hp->fn_malloc, LIB_C);
		LD_LIB_FIND_FN_ADDR("realloc", hp->fn_realloc, LIB_C);
		LD_LIB_FIND_FN_ADDR("free", hp->fn_free, LIB_C);
	}
	if (ld_found) {
		LD_LIB_FIND_FN_ADDR("malloc", hp->fn_malloc, LIB_LD);
		LD_LIB_FIND_FN_ADDR("realloc", hp->fn_realloc, LIB_LD);
		LD_LIB_FIND_FN_ADDR("free", hp->fn_free, LIB_LD);
	}
	if (!hp->fn_malloc || !hp->fn_realloc || !hp->fn_free) {
		if (verbose > 0)
			fprintf(stderr, "[%s:%d] Some memory allocation routines are"
					" unavailable. Cannot proceed.\n", __func__, __LINE__);
		return -1;
	}
	if (dl_found) {
		LD_LIB_FIND_FN_ADDR("dlopen", hp->fn_dlopen, LIB_DL);
		LD_LIB_FIND_FN_ADDR("dlclose", hp->fn_dlclose, LIB_DL);
		LD_LIB_FIND_FN_ADDR("dlsym", hp->fn_dlsym, LIB_DL);
	} else {
		LD_LIB_FIND_FN_ADDR("__libc_dlopen_mode", hp->fn_dlopen, LIB_C);
		LD_LIB_FIND_FN_ADDR("__libc_dlclose", hp->fn_dlclose, LIB_C);
		LD_LIB_FIND_FN_ADDR("__libc_dlsym", hp->fn_dlsym, LIB_C);
	}
	if (!hp->fn_dlopen || !hp->fn_dlsym) {
		if (verbose > 0)
			fprintf(stderr, "[%s:%d] Dynamic Library loading routines were not"
					" found. Cannot proceed.\n", __func__, __LINE__);
		return -1;
	}
	if (pthread_found) {
		LD_LIB_FIND_FN_ADDR("pthread_create", hp->fn_pthread_create,
							LIB_PTHREAD);
		LD_LIB_FIND_FN_ADDR("pthread_detach", hp->fn_pthread_detach,
							LIB_PTHREAD);
	} else {
		hp->fn_pthread_create = hp->fn_pthread_detach = 0;
	}
	if (verbose > 1) {
		if (hp->fn_pthread_create && hp->fn_pthread_detach)
			fprintf(stderr, "[%s:%d] Pthread's symbol found. Do not need more"
					" magic.\n", __func__, __LINE__);
		else
			fprintf(stderr, "[%s:%d] Pthread's symbol not found. Will disable"
					" pthread usage in injection.\n", __func__, __LINE__);
	}
#undef LD_PROCMAPS_FIND_LIB
#undef LD_LIB_FIND_FN_ADDR
	return 0;
}

void hotpatch_version(int *major, int *minor)
{
	if (major)
		*major = HOTPATCH_MAJOR_VERSION;
	if (minor)
		*minor = HOTPATCH_MINOR_VERSION;
}

hotpatch_t *hotpatch_create(pid_t pid, int verbose)
{
	int rc = 0;
	hotpatch_t *hp = NULL;
	do {
		char filename[OS_MAX_BUFFER];
		if (pid <= 0) {
			LOG_ERROR_INVALID_PID(pid);
			break;
		}
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename), "/proc/%d/exe", pid);
		if (verbose > 3)
			fprintf(stderr, "[%s:%d] Exe symlink for pid %d : %s\n", __func__,
					__LINE__, pid, filename);
		hp = malloc(sizeof(*hp));
		if (!hp) {
			LOG_ERROR_OUT_OF_MEMORY;
			rc = -1;
			break;
		}
		memset(hp, 0, sizeof(*hp));
		hp->verbose = verbose;
		hp->pid = pid;
		hp->is64 = HOTPATCH_EXE_IS_NEITHER;
		hp->exe_symbols = exe_load_symbols(filename, hp->verbose,
				&hp->exe_symbols_num,
				&hp->exe_entry_point,
				&hp->exe_interp,
				&hp->is64);
		if (!hp->exe_symbols) {
			fprintf(stderr, "[%s:%d] Unable to find any symbols in exe.\n",
					__func__, __LINE__);
			rc = -1;
			break;
		}
		if (hp->exe_entry_point == 0) {
			fprintf(stderr, "[%s:%d] Entry point is 0. Invalid.\n",
					__func__, __LINE__);
			rc = -1;
			break;
		}
		LOG_INFO_HEADERS_LOADED(verbose);
		hp->ld_maps = ld_load_maps(hp->pid, hp->verbose, &hp->ld_maps_num);
		if (!hp->ld_maps) {
			fprintf(stderr, "[%s:%d] Unable to load data in "
					"/proc/%d/maps.\n", __func__, __LINE__, pid);
			rc = -1;
			break;
		}
		if (verbose > 2)
			fprintf(stderr, "[%s:%d] /proc/%d/maps loaded.\n",
					__func__, __LINE__, pid);
		if (hp->exe_symbols && hp->exe_symbols_num > 0) {
			qsort(hp->exe_symbols, hp->exe_symbols_num,
					sizeof(*hp->exe_symbols), elf_symbol_cmpqsort);
		}
		if (hotpatch_gather_functions(hp) < 0) {
			fprintf(stderr, "[%s:%d] Unable to find all the functions"
					" needed. Cannot proceed.\n", __func__, __LINE__);
			rc = -1;
			break;
		}
		if (rc < 0) {
			hotpatch_destroy(hp);
			hp = NULL;
		}
	} while (0);
	return hp;
}

void hotpatch_destroy(hotpatch_t *hp)
{
	if (hp) {
		size_t idx;
		if (hp->attached)
			hotpatch_detach(hp);
		if (hp->exe_symbols) {
			for (idx = 0; idx < hp->exe_symbols_num; ++idx) {
				free(hp->exe_symbols[idx].name);
				hp->exe_symbols[idx].name = NULL;
			}
			free(hp->exe_symbols);
		}
		hp->exe_symbols = NULL;
		hp->exe_symbols_num = 0;
		if (hp->exe_interp.name) {
			free(hp->exe_interp.name);
			hp->exe_interp.name = NULL;
		}
		for (idx = 0; idx < HOTPATCH_LIB_MAX; ++idx) {
				if (hp->libs[idx].pathname)
					free(hp->libs[idx].pathname);
				hp->libs[idx].pathname = NULL;
		}
		memset(hp->libs, 0, sizeof(hp->libs));
		if (hp->ld_maps) {
			ld_free_maps(hp->ld_maps, hp->ld_maps_num);
			hp->ld_maps = NULL;
			hp->ld_maps_num = 0;
		}
		free(hp);
		hp = NULL;
	}
}

uintptr_t hotpatch_read_symbol(hotpatch_t *hp, const char *symbol, int *type, size_t *sz)
{
	uintptr_t ptr = 0;
	size_t idx = 0;
	if (!hp || !symbol || !hp->exe_symbols) {
		if (hp->verbose > 2)
			fprintf(stderr, "[%s:%d] Invalid arguments.\n", __func__, __LINE__);
		return (uintptr_t)0;
	}
	for (idx = 0; idx < hp->exe_symbols_num; ++idx) {
		const char *name = hp->exe_symbols[idx].name;
		if (strcmp(name, symbol) == 0) {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] Found %s in symbol list at "LU"\n",
						__func__, __LINE__, symbol, idx);
			ptr = hp->exe_symbols[idx].address;
			if (type)
				*type = hp->exe_symbols[idx].type;
			if (sz)
				*sz = hp->exe_symbols[idx].size;
			break;
		}
	}
	if (hp->verbose > 2)
		fprintf(stderr, "[%s:%d] Symbol %s has address 0x"LX"\n", __func__,
				__LINE__, symbol, ptr);
	return ptr;
}

uintptr_t hotpatch_get_entry_point(hotpatch_t *hp)
{
	return hp ? hp->exe_entry_point : 0;
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


static int hp_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		int err = errno;
		fprintf(stderr,
				"[%s:%d] Ptrace Attach for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	return 0;
}

static int hp_detach(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		int err = errno;
		fprintf(stderr,
				"[%s:%d] Ptrace Detach for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	return 0;
}

static int hp_exec(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		int err = errno;
		fprintf(stderr,
				"[%s:%d] Ptrace Continue for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	return 0;
}

static int hp_wait(pid_t pid)
{
	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		int err = errno;
		fprintf(stderr, "[%s:%d] Waitpid for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		fprintf(stderr, "[%s:%d] PID %d was terminated.\n",
				__func__, __LINE__, pid);
		return -1;
	}
	return 0;
}

static int hp_get_regs(pid_t pid, struct user *regs)
{
	if (!regs)
		return -1;
	memset(regs, 0, sizeof(*regs));
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		int err = errno;
		fprintf(stderr,
				"[%s:%d] Ptrace Getregs for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	return 0;
}

static int hp_set_regs(pid_t pid, const struct user *regs)
{
	if (!regs)
		return -1;
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		int err = errno;
		fprintf(stderr,
				"[%s:%d] Ptrace Setregs for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	return 0;
}

static int hp_copydata(pid_t pid, uintptr_t target,
		const unsigned char *data, size_t datasz, int verbose)
{
	size_t pos = 0;
	size_t idx = 0;
	while (pos < datasz) {
		size_t pokedata = 0, jdx = 0;
		const size_t pksz = sizeof(size_t);
		for (jdx = 0; jdx < pksz && pos < datasz; ++jdx)
			((unsigned char *)&pokedata)[jdx] = data[pos++];
		if (verbose > 2)
			fprintf(stderr, "[%s:%d] Pokedata: %p\n", __func__, __LINE__,
				(void *)pokedata);
		if (ptrace(PTRACE_POKEDATA, pid, target + idx,
					pokedata) < 0) {
			int err = errno;
			fprintf(stderr,
				"[%s:%d] Ptrace PokeText for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
			return -1;
		}
		idx += sizeof(size_t);
	}
	return 0;
}

static int hp_peekdata(pid_t pid, uintptr_t target, uintptr_t *outpeek,
						int verbose)
{
	int err = 0;
	long peekdata = ptrace(PTRACE_PEEKDATA, pid, target, NULL);
	err = errno;
	if (verbose > 2)
		fprintf(stderr, "[%s:%d] Peekdata: %p\n", __func__, __LINE__,
			(void *)peekdata);
	if (peekdata == -1 && err != 0) {
		fprintf(stderr,
				"[%s:%d] Ptrace PeekText for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	if (outpeek)
		*outpeek = peekdata;
	else
		fprintf(stderr, "[%s:%d] Invalid arguments.\n", __func__, __LINE__);
	return outpeek ? 0 : -1;
}

static int hp_pokedata(pid_t pid, uintptr_t target, uintptr_t pokedata,
						int verbose)
{
	int err = 0;
	if (verbose > 2)
		fprintf(stderr, "[%s:%d] Pokedata: %p\n", __func__, __LINE__,
			(void *)pokedata);
	if (ptrace(PTRACE_POKEDATA, pid, target, (void *)pokedata) < 0) {
		fprintf(stderr,
				"[%s:%d] Ptrace PokeText for PID %d failed with error: %s\n",
				__func__, __LINE__, pid, strerror(err));
		return -1;
	}
	return 0;
}

int hotpatch_set_execution_pointer(hotpatch_t *hp, uintptr_t ptr)
{
#undef HP_REG_IP_STR
#undef HP_REG_IP
#undef HP_REG_SP
#undef HP_REG_AX
#if __WORDSIZE == 64
	#define HP_REG_IP_STR "RIP"
	#define HP_REG_IP(A) A.regs.rip
	#define HP_REG_SP(A) A.regs.rsp
	#define HP_REG_AX(A) A.regs.rax
#else
	#define HP_REG_IP_STR "EIP"
	#define HP_REG_IP(A) A.regs.eip
	#define HP_REG_SP(A) A.regs.esp
	#define HP_REG_AX(A) A.regs.eax
#endif
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
				fprintf(stderr, "[%s:%d] %s is %p\n", __func__, __LINE__,
						HP_REG_IP_STR,
						(void *)HP_REG_IP(regs));
			if (ptr == hp->exe_entry_point)
				ptr += sizeof(void *);
			HP_REG_IP(regs) = ptr;
			if (ptrace(PTRACE_SETREGS, hp->pid, NULL, &regs) < 0) {
				int err = errno;
				fprintf(stderr, "[%s:%d] Ptrace setregs failed with error %s\n",
						__func__, __LINE__, strerror(err));
			} else {
				if (hp->verbose > 0)
					fprintf(stderr, "[%s:%d] Set %s to 0x"LX"\n",
							__func__, __LINE__, HP_REG_IP_STR, ptr);
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

int hotpatch_inject_library(hotpatch_t *hp, const char *dll, const char *symbol,
							const unsigned char *data, size_t datalen,
							uintptr_t *outaddr, uintptr_t *outres)
{
	size_t dllsz = 0;
	size_t symsz = 0;
	size_t datasz = 0;
	size_t tgtsz = 0;
	int rc = 0;
	unsigned char *mdata = NULL;
	if (!dll || !hp) {
		fprintf(stderr, "[%s:%d] Invalid arguments.\n", __func__, __LINE__);
		return -1;
	}
	if (!hp->fn_malloc || !hp->fn_dlopen) {
		fprintf(stderr, "[%s:%d] No malloc/dlopen found.\n", __func__,
				__LINE__);
		return -1;
	}
	/* calculate the size to allocate */
	dllsz = strlen(dll) + 1;
	symsz = symbol ? (strlen(symbol) + 1) : 0;
	datasz = data ? datalen : 0;
	tgtsz = dllsz + symsz + datasz + 32; /* general buffer */
	tgtsz = (tgtsz > 1024) ? tgtsz : 1024;
	/* align the memory */
	tgtsz += (tgtsz % sizeof(void *) == 0) ? 0 :
			 (sizeof(void *) - (tgtsz % sizeof(void *)));
	mdata = calloc(sizeof(unsigned char), tgtsz);
	if (!mdata) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	memcpy(mdata, dll, dllsz);
	if (symbol) {
		memcpy(mdata + dllsz, symbol, symsz);
	}
	if (data) {
		memcpy(mdata + dllsz + symsz, data, datasz);
	}
	if (hp->verbose > 0)
		fprintf(stderr, "[%s:%d] Allocating "LU" bytes in the target.\n",
				__func__, __LINE__, tgtsz);
	do {
		/* The stack is read-write and not executable */
		struct user iregs; /* intermediate registers */
		struct user oregs; /* original registers */
		int verbose = hp->verbose;
		uintptr_t result = 0;
		uintptr_t stack[4] = { 0, 0, 0, 0}; /* max arguments of the functions we
											   are using */
		uintptr_t heapptr = 0;
		int idx = 0;
#undef HP_SETEXECWAITGET
#undef HP_NULLIFYSTACK
#undef HP_PASS_ARGS2FUNC
#define HP_NULLIFYSTACK() \
do { \
	uintptr_t nullcode = 0; \
	if (verbose > 1) \
		fprintf(stderr, "[%s:%d] Copying Null to stack.\n", \
			__func__, __LINE__); \
	if ((rc = hp_pokedata(hp->pid, HP_REG_SP(iregs), nullcode, verbose)) < 0) \
		break; \
} while (0)

#define HP_SETEXECWAITGET(fn) \
do { \
	if (verbose > 1) \
		fprintf(stderr, "[%s:%d] Setting registers and invoking %s.\n", \
			__func__, __LINE__, fn); \
	if ((rc = hp_set_regs(hp->pid, &iregs)) < 0) \
		break; \
	if (verbose > 1) \
		fprintf(stderr, "[%s:%d] Executing...\n", __func__, __LINE__); \
	if ((rc = hp_exec(hp->pid)) < 0) \
		break; \
	if (verbose > 1) \
		fprintf(stderr, "[%s:%d] Waiting...\n", __func__, __LINE__); \
	if ((rc = hp_wait(hp->pid)) < 0) \
		break; \
	if (verbose > 1) \
		fprintf(stderr, "[%s:%d] Getting registers.\n", __func__, __LINE__); \
	if ((rc = hp_get_regs(hp->pid, &iregs)) < 0) \
		break; \
} while (0)
#if __WORDSIZE == 64
	#define HP_PASS_ARGS2FUNC(A,FN,ARG1,ARG2) \
	do { \
		A.regs.rsi = ARG2; \
		A.regs.rdi = ARG1; \
		A.regs.rip = FN; \
		A.regs.rax = 0; \
	} while (0)
    #define HP_REDZONE 128
        /* David Yeager pointed this out. http://en.wikipedia.org/wiki/Red_zone_(computing) */
#else /* __WORDSIZE == 64 */
	#define HP_PASS_ARGS2FUNC(A,FN,ARG1,ARG2) \
	do { \
		if (verbose > 1) \
			fprintf(stderr, "[%s:%d] Copying Arg 1 to stack.\n", \
				__func__, __LINE__); \
		if ((rc = hp_pokedata(hp->pid, HP_REG_SP(iregs) + sizeof(size_t), \
							  ARG1, verbose)) < 0) \
			break; \
		if (verbose > 1) \
			fprintf(stderr, "[%s:%d] Copying Arg 2 to stack.\n", \
				__func__, __LINE__); \
		if ((rc = hp_pokedata(hp->pid, HP_REG_SP(iregs) + 2 * sizeof(size_t), \
							  ARG2, verbose)) < 0) \
			break; \
		A.regs.eip = FN; \
		A.regs.eax = 0; \
	} while (0)
    #define HP_REDZONE 0
#endif /* __WORDSIZE == 64 */
		/* Prepare the child for injection */
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Attaching to PID %d\n", __func__,
					__LINE__, hp->pid);
		if ((rc = hp_attach(hp->pid)) < 0)
			break;
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Waiting...\n", __func__, __LINE__);
		if ((rc = hp_wait(hp->pid)) < 0)
			break;
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Getting original registers.\n",
					__func__, __LINE__);
		if ((rc = hp_get_regs(hp->pid, &oregs)) < 0)
			break;
		memcpy(&iregs, &oregs, sizeof(oregs));
        HP_REG_SP(iregs) -= HP_REDZONE;
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Copying stack out.\n", __func__, __LINE__);
		for (idx = 0; idx < sizeof(stack)/sizeof(uintptr_t); ++idx) {
			if ((rc = hp_peekdata(hp->pid, HP_REG_SP(iregs) +
							idx * sizeof(size_t), &stack[idx], verbose)) < 0)
				break;
		}
		if (rc < 0)
			break;
		/* Call malloc */
		HP_NULLIFYSTACK();
		HP_PASS_ARGS2FUNC(iregs, hp->fn_malloc, tgtsz, 0);
		HP_SETEXECWAITGET("malloc");
		result = HP_REG_AX(iregs);
		heapptr = HP_REG_AX(iregs); /* keep a copy of this pointer */
		/* Copy data to the malloced area */
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Copying "LU" bytes to 0x"LX".\n", __func__,
					__LINE__, tgtsz, result);
		if (!result)
			break;
		if ((rc = hp_copydata(hp->pid, result, mdata, tgtsz, verbose)) < 0)
			break;
		/* Call dlopen */
		HP_NULLIFYSTACK();
		HP_PASS_ARGS2FUNC(iregs, hp->fn_dlopen, result /* value from malloc */,
					(RTLD_LAZY | RTLD_GLOBAL));
		HP_SETEXECWAITGET("dlopen");
		result = HP_REG_AX(iregs);
		if (verbose > 0)
			fprintf(stderr, "[%s:%d] Dll opened at 0x"LX"\n", __func__, __LINE__,
				result);
		if (outaddr)
			*outaddr = result;
		/* Call dlsym */
		if (symbol && hp->fn_dlsym && result != 0) {
			HP_NULLIFYSTACK();
			HP_PASS_ARGS2FUNC(iregs, hp->fn_dlsym,
					result /* value from dlopen */,
					(heapptr + dllsz));
			HP_SETEXECWAITGET("dlsym");
			result = HP_REG_AX(iregs);
			if (verbose > 0)
				fprintf(stderr, "[%s:%d] Symbol %s found at 0x"LX"\n",
						__func__, __LINE__, symbol, result);
			if (result != 0) {
				HP_NULLIFYSTACK();
				if (datasz > 0) {
					HP_PASS_ARGS2FUNC(iregs, result /* value from dlsym */,
								(heapptr + dllsz + symsz), datasz);
				} else {
					HP_PASS_ARGS2FUNC(iregs, result /* value from dlsym */,
								0, 0);
				}
				HP_SETEXECWAITGET(symbol);
				result = HP_REG_AX(iregs);
				if (verbose > 0)
					fprintf(stderr, "[%s:%d] Return value from invoking %s(): %p\n",
							__func__, __LINE__, symbol, (void *)result);
				if (outres)
					*outres = result;
			} else {
				if (verbose > 0)
					fprintf(stderr, "[%s:%d] Unable to find %s(). Dll might "
							"already have been injected earlier.\n",
							__func__, __LINE__, symbol);
				if (outres)
					*outres = 0;
			}
		} else {
			if (verbose > 1 && symbol)
				fprintf(stderr, "[%s:%d] %s not invoked as dlsym() wasn't "
						"found.\n", __func__, __LINE__, symbol);
			else if (verbose > 1)
				fprintf(stderr, "[%s:%d] No symbol was specified. _init() might"
						" have been invoked.\n", __func__, __LINE__);
			if (outres)
				*outres = 0;
		}
		/* Original reset */
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Setting original registers.\n",
					__func__, __LINE__);
		if ((rc = hp_set_regs(hp->pid, &oregs)) < 0) {
			fprintf(stderr, "[%s:%d] PID %d will be unstable.\n", __func__,
					__LINE__, hp->pid);
			break;
		}
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Copying stack back.\n",
					__func__, __LINE__);
		for (idx = 0; idx < sizeof(stack)/sizeof(uintptr_t); ++idx) {
			if ((rc = hp_pokedata(hp->pid, HP_REG_SP(oregs) - HP_REDZONE
                            + idx * sizeof(size_t), stack[idx], verbose)) < 0)
				break;
		}
		if (rc < 0)
			break;
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Executing...\n", __func__, __LINE__);
		if ((rc = hp_exec(hp->pid)) < 0)
			break;
	} while (0);
	if (rc < 0) {
		if (hp->verbose > 1)
			fprintf(stderr, "[%s:%d] Detaching from PID %d\n", __func__,
					__LINE__, hp->pid);
		if (hp_detach(hp->pid) < 0) {
			if (hp->verbose > 0)
				fprintf(stderr, "[%s:%d] Error detaching from PID %d\n", __func__,
						__LINE__, hp->pid);
			rc = -1;
		}
	}
	if (mdata)
		free(mdata);
	mdata = NULL;
#undef HP_PASS_ARGS2FUNC
#undef HP_SETEXECWAITGET
#undef HP_NULLIFYSTACK
#undef HP_REG_IP_STR
#undef HP_REG_IP
#undef HP_REG_SP
#undef HP_REG_AX
#undef HP_REDZONE
	return rc;
}
