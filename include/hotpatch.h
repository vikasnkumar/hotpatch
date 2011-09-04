/*
 *  hotpatch is a dll injection strategy.
 *  Copyright (C) 2010-2011 Vikas Naresh Kumar
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __LIBHOTPATCH_H__
#define __LIBHOTPATCH_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <sys/types.h>

#define HOTPATCH_MAJOR_VERSION 0
#define HOTPATCH_MINOR_VERSION 1

enum {
	HOTPATCH_SYMBOL_IS_UNKNOWN,
	HOTPATCH_SYMBOL_IS_FUNCTION,
	HOTPATCH_SYMBOL_IS_FILENAME,
	HOTPATCH_SYMBOL_IS_SECTION
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
 * Inject a shared object into the process and invoke the given symbol with
 * arguments
 */
int hotpatch_insert(hotpatch_t *hotpatch, const char *dll, const char *symbol, void *arg);

#ifdef __cplusplus
} /* end of extern C */
#endif /* __cplusplus */

#endif /* __LIBHOTPATCH_H__ */
