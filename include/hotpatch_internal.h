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
#ifndef __LIBHOTPATCH_INTERNAL_H__
#define __LIBHOTPATCH_INTERNAL_H__

#include <hotpatch_config.h>

#define OS_MAX_BUFFER 512

#undef LOG_ERROR_INVALID_PID
#define LOG_ERROR_INVALID_PID(A) do { \
	fprintf(stderr, "[%s:%d] Invalid PID: %d\n", __func__, __LINE__, A); \
} while (0)

#undef LOG_ERROR_OUT_OF_MEMORY
#define LOG_ERROR_OUT_OF_MEMORY do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] Out of memory. Error: %s\n", __func__, __LINE__,\
			strerror(err)); \
} while (0)

#undef LOG_ERROR_FILE_OPEN
#define LOG_ERROR_FILE_OPEN(FF) do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File(%s) open error. Error: %s\n", __func__, __LINE__,\
			FF, strerror(err)); \
} while (0)

#undef LOG_ERROR_FILE_SEEK
#define LOG_ERROR_FILE_SEEK do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File seek error. Error: %s\n", __func__, __LINE__,\
			strerror(err)); \
} while (0)

#undef LOG_ERROR_FILE_READ
#define LOG_ERROR_FILE_READ do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File read error. Error: %s\n", __func__, __LINE__,\
			strerror(err)); \
} while (0)

#undef LOG_ERROR_UNSUPPORTED_PROCESSOR
#define LOG_ERROR_UNSUPPORTED_PROCESSOR do { \
	fprintf(stderr, \
			"[%s:%d] Only 32/64-bit Intel X86/X86-64 processors are supported.\n",\
			__func__, __LINE__); \
} while (0)
#define LOG_INFO_HEADERS_LOADED(verbose) do { \
	if (verbose > 2) \
		fprintf(stderr, "[%s:%d] Exe headers loaded.\n", __func__, __LINE__); \
} while (0)

struct ld_procmaps;

enum elf_bit {
	HOTPATCH_EXE_IS_NEITHER,
	HOTPATCH_EXE_IS_32BIT,
	HOTPATCH_EXE_IS_64BIT
};

struct elf_symbol {
	char *name; /* null terminated symbol name */
	uintptr_t address; /* address at which it is available */
	int type; /* type of symbol */
	size_t size; /* size of the symbol if available */
};

struct elf_interp {
	char *name;
	size_t length;
	uintptr_t ph_addr;
};

struct ld_library {
	char *pathname;
	size_t length;
	ino_t inode;
	uintptr_t addr_begin;
	uintptr_t addr_end;
};

enum {
	HOTPATCH_LIB_LD = 0,
	HOTPATCH_LIB_C,
	HOTPATCH_LIB_DL,
	HOTPATCH_LIB_PTHREAD,
	HOTPATCH_LIB_MAX
};

enum {
	HOTPATCH_SYMBOL_IS_UNKNOWN,
	HOTPATCH_SYMBOL_IS_FUNCTION,
	HOTPATCH_SYMBOL_IS_FILENAME,
	HOTPATCH_SYMBOL_IS_SECTION,
	HOTPATCH_SYMBOL_IS_OBJECT
};

struct hotpatch_is_opaque {
	pid_t pid;
	int verbose;
	enum elf_bit is64;
	struct elf_symbol *exe_symbols;
	size_t exe_symbols_num;
	uintptr_t exe_entry_point;
	struct elf_interp exe_interp; /* dynamic loader from .interp in the exe */
	struct ld_procmaps *ld_maps;
	size_t ld_maps_num;
	struct ld_library libs[HOTPATCH_LIB_MAX];
	/* addresses useful */
	uintptr_t fn_malloc;
	uintptr_t fn_realloc;
	uintptr_t fn_free;
	uintptr_t fn_dlopen;
	uintptr_t fn_dlclose;
	uintptr_t fn_dlsym;
	uintptr_t fn_pthread_create;
	uintptr_t fn_pthread_detach;
	/* actions */
	bool attached;
	bool inserted;
};

struct elf_symbol *exe_load_symbols(const char *filename, int verbose,
										size_t *sym_count,
										uintptr_t *entry_point,
										struct elf_interp *interp,
										enum elf_bit *is64);

struct ld_procmaps *ld_load_maps(pid_t pid, int verbose, size_t *num);

void ld_free_maps(struct ld_procmaps *, size_t num);

/* the full path of the library needs to be given. */
int ld_find_library(const struct ld_procmaps *, const size_t num,
					const char *libpath, bool inode_match,
					struct ld_library *lib, int verbose);

/* finds the address of the symbol in the library if it exists */
uintptr_t ld_find_address(const struct ld_library *hpl, const char *symbol,
						  int verbose);

int elf_symbol_cmpqsort(const void *p1, const void *p2);
#endif /* __LIBHOTPATCH_INTERNAL_H__ */
