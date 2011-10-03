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
#ifndef __LIBHOTPATCH_H__
#define __LIBHOTPATCH_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <sys/types.h>

#define HOTPATCH_MAJOR_VERSION 0
#define HOTPATCH_MINOR_VERSION 1

#ifndef HOTPATCH_LINUX_START
	#define HOTPATCH_LINUX_START "_start"
#endif

enum {
	HOTPATCH_SYMBOL_IS_UNKNOWN,
	HOTPATCH_SYMBOL_IS_FUNCTION,
	HOTPATCH_SYMBOL_IS_FILENAME,
	HOTPATCH_SYMBOL_IS_SECTION,
	HOTPATCH_SYMBOL_IS_OBJECT
};

typedef struct hotpatch_is_opaque hotpatch_t;
/* Create the hotpatch object for the running process whose PID is given as an
 * argument. Returns a pointer to an opaque object that must be freed by
 * hotpatch_delete() function later to conserve memory.
 */
hotpatch_t *hotpatch_create(pid_t, int);
/*
 * delete memory and close all open handles related to the hotpatch'ed process.
 * This can lead to the hotpatch'ed process to be unstable if not done in the same
 * thread as create function above.
 */
void hotpatch_destroy(hotpatch_t *hotpatch);
/* finds the symbol in the symbol table of executable and returns the memory
 * location of it. On a 64-bit system the running process can be 32 or 64 bit,
 * and hence they both need to be handled correctly or even simultaneously.
 * Returns not only the location of the symbol but also the type and size
 */
uintptr_t hotpatch_read_symbol(hotpatch_t *, const char *symbol, int *symtype,
							   size_t *symsize);
/*
 * Get the entry point of the executable in question
 */
uintptr_t hotpatch_get_entry_point(hotpatch_t *);
/*
 * Attach to the process that you wanted to hotpatch. Returns 0 on success and 1
 * on failure.
 */
int hotpatch_attach(hotpatch_t *);
/*
 * Detach from the process that you wanted to hotpatch. Returns -1 on failure
 * or if nothing was attached earlier. Returns 0 if detaching succeeded.
 */
int hotpatch_detach(hotpatch_t *);
/*
 * Sets the execution pointer to point to the address given by the user.
 * Returns 0 on success and -1 on failure.
 */
int hotpatch_set_execution_pointer(hotpatch_t *, uintptr_t location);
/*
 * Inject custom code at the given location which needs to be the execution
 * pointer and will be where the RIP/EIP register will be set to point to for
 * execution. Return 0 on success and -1 on failure.
 * The code will start executing if the execute flag is set to 1.
 *
 */
int hotpatch_inject_code_at(hotpatch_t *, uintptr_t location,
				const unsigned char *code, size_t len, int8_t execute);
/*
 * Inject a shared object into the process and invoke the given symbol without
 * arguments. No thread will be created by hotpatch.
 * If the symbol is NULL, then _init() is expected to be in the library.
 */
int hotpatch_inject_library(hotpatch_t *, const char *dll, const char *symbol);
/*
 * If the target process has linked with pthread, then create a thread using
 * that. Load the dll using dlopen and get the symbol accordingly.
 */
int hotpatch_create_pthread(hotpatch_t *, const char *dll, const char *symbol);
#ifdef __cplusplus
} /* end of extern C */
#endif /* __cplusplus */

#endif /* __LIBHOTPATCH_H__ */
