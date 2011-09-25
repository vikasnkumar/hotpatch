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

struct hotpatch_is_opaque {
	pid_t pid;
	int verbose;
	enum {
		HOTPATCH_EXE_IS_NEITHER,
		HOTPATCH_EXE_IS_32BIT,
		HOTPATCH_EXE_IS_64BIT
	} is64;
	int fd_exe;
	off_t proghdr_offset;
	void *proghdrs; /* program headers */
	size_t proghdr_num;
	size_t proghdr_size; /* total buffer size */
	off_t sechdr_offset;
	void *sechdrs; /* section headers */
	size_t sechdr_num;
	size_t sechdr_size; /* total buffer size */
	size_t secnametbl_idx;
	char *strsectbl; /* string table for section names */
	size_t strsectbl_size;
	char *exepath;
	struct hotpatch_symbol {
		char *name; /* null terminated symbol name */
		uintptr_t address; /* address at which it is available */
		int type; /* type of symbol */
		size_t size; /* size of the symbol if available */
	} *symbols;
	size_t symbols_num;
	uintptr_t entry_point;
	struct hotpatch_loader {
		char *name;
		size_t length;
		uintptr_t ph_addr;
	} interp; /* dynamic loader from .interp */
	struct ld_procmaps *ld_maps;
	size_t ld_maps_num;
	struct hotpatch_library {
		char *pathname;
		size_t length;
		ino_t inode;
		uintptr_t addr_begin;
		uintptr_t addr_end;
	} *libs;
	size_t libs_num; /* 0th element is the loader */
	/* actions */
	bool attached;
	bool inserted;
};

int exe_open_file(pid_t pid, int verbose);

int exe_load_headers(struct hotpatch_is_opaque *hp);

struct ld_procmaps *ld_load_maps(pid_t pid, int verbose, size_t *num);

void ld_free_maps(struct ld_procmaps *, size_t num);

/* the full path of the library needs to be given. */
int ld_find_library(const struct ld_procmaps *, const size_t num,
					const char *libpath, bool inode_match,
					struct hotpatch_library *lib, int verbose);

/* finds the address of the symbol in the library if it exists */
uintptr_t ld_find_address(const struct hotpatch_library *hpl, const char *symbol,
						  int verbose);

#endif /* __LIBHOTPATCH_INTERNAL_H__ */
