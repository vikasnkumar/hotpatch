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

enum {
    PROCMAPS_PERMS_NONE  = 0x0,
    PROCMAPS_PERMS_READ  = 0x1,
    PROCMAPS_PERMS_EXEC  = 0x2,
    PROCMAPS_PERMS_WRITE = 0x4,
    PROCMAPS_PERMS_PVT   = 0x8
};

enum {
    PROCMAPS_FILETYPE_UNKNOWN,
    PROCMAPS_FILETYPE_EXE,
    PROCMAPS_FILETYPE_LIB,
    PROCMAPS_FILETYPE_DATA,
    PROCMAPS_FILETYPE_VDSO,
    PROCMAPS_FILETYPE_HEAP,
    PROCMAPS_FILETYPE_STACK,
    PROCMAPS_FILETYPE_SYSCALL
};

struct ld_procmaps {
    uintptr_t addr_begin;
    uintptr_t addr_end;
    bool addr_valid;
    int permissions;
    off_t offset;
    int device_major;
    int device_minor;
    ino_t inode;
    char *pathname;
    size_t pathname_sz;
    int filetype;
};

void ld_procmaps_dump(struct ld_procmaps *pm)
{
    if (!pm)
        return;
    fprintf(stderr, "[%s:%d] Pathname: %s\n", __func__, __LINE__,
			pm->pathname ? pm->pathname : "Unknown");
    fprintf(stderr, "[%s:%d] Address Start: %lx End: %lx Valid:"
					"	%d Offset: %ld\n", __func__, __LINE__,
			pm->addr_begin, pm->addr_end, pm->addr_valid, pm->offset);
    fprintf(stderr, "[%s:%d] Device Major: %d Minor: %d\n",
			__func__, __LINE__, pm->device_major, pm->device_minor);
    fprintf(stderr, "[%s:%d] Inode: %ld\n", __func__, __LINE__,
			pm->inode);
    fprintf(stderr, "[%s:%d] Permissions: Read(%d) Write(%d) "
					"Execute(%d) Private(%d)\n", __func__, __LINE__,
            (pm->permissions & PROCMAPS_PERMS_READ) ? 1 : 0,
            (pm->permissions & PROCMAPS_PERMS_WRITE) ? 1 : 0,
            (pm->permissions & PROCMAPS_PERMS_EXEC) ? 1 : 0,
            (pm->permissions & PROCMAPS_PERMS_PVT) ? 1 : 0);
    fprintf(stderr, "[%s:%d] Pathname length: %ld\n", __func__, __LINE__,
			pm->pathname_sz);
    fprintf(stderr, "[%s:%d] Filetype: %d\n", __func__, __LINE__,
			pm->filetype);
}

int ld_procmaps_parse(char *buf, size_t bufsz, struct ld_procmaps *pm,
                 const char *appname, int verbose)
{
    if (!buf || !pm) {
		if (verbose > 2)
			fprintf(stderr, "[%s:%d] Invalid arguments.\n", __func__, __LINE__);
        return -1;
	}
    /* this is hardcoded parsing of the maps file */
    do {
        char *token = NULL;
        char *save = NULL;
        int idx, err;
        memset(pm, 0, sizeof(*pm));
        token = strtok_r(buf, "-", &save);
        if (!token) break;
		errno = 0;
        pm->addr_begin = (uintptr_t)strtoul(token, NULL, 16);
		err = errno;
        pm->addr_valid = (err == ERANGE || err == EINVAL) ? false : true;
        if (!pm->addr_valid) {
			if (verbose > 2)
				fprintf(stderr, "[%s:%d] Strtoul error(%s) in parsing %s\n",
						__func__, __LINE__, strerror(err), token);
        }
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
		errno = 0;
        pm->addr_end = (intptr_t)strtoul(token, NULL, 16);
		err = errno;
        pm->addr_valid = (err == ERANGE || err == EINVAL) ? false : true;
        if (!pm->addr_valid) {
			if (verbose > 2)
				fprintf(stderr, "[%s:%d] Strtoul error(%s) in parsing %s\n",
						__func__, __LINE__, strerror(err), token);
        }
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->permissions = PROCMAPS_PERMS_NONE;
        for (idx = strlen(token) - 1; idx >= 0; --idx) {
            switch (token[idx]) {
            case 'r':
                pm->permissions |= PROCMAPS_PERMS_READ;
                break;
            case 'w':
                pm->permissions |= PROCMAPS_PERMS_WRITE;
                break;
            case 'x':
                pm->permissions |= PROCMAPS_PERMS_EXEC;
                break;
            case 'p':
                pm->permissions |= PROCMAPS_PERMS_PVT;
                break;
            case '-':
                break;
            default:
				if (verbose > 2)
	                fprintf(stderr, "[%s:%d] Unknown flag: %c\n", __func__,
							__LINE__, token[idx]);
                break;
            }
        }
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
		errno = 0;
        pm->offset = (off_t)strtoul(token, NULL, 16);
		err = errno;
        if (err == ERANGE || err == EINVAL) {
			if (verbose > 2)
				fprintf(stderr, "[%s:%d] Strtoul error(%s) in parsing %s\n",
						__func__, __LINE__, strerror(err), token);
        }
        token = strtok_r(NULL, ":", &save);
        if (!token) break;
        pm->device_major = (int)strtol(token, NULL, 10);
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->device_minor = (int)strtol(token, NULL, 10);
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->inode = (ino_t)strtoul(token, NULL, 10);
        token = strtok_r(NULL, "\n", &save);
        if (!token) break;
        pm->pathname_sz = strlen(token);
        pm->pathname = calloc(sizeof(char), pm->pathname_sz + 1);
        if (!pm->pathname) {
			LOG_ERROR_OUT_OF_MEMORY;
            pm->pathname = NULL;
            pm->pathname_sz = 0;
            break;
        }
        /* trim the extra spaces out */
        save = token;
        /* find the real path names */
        if ((token = strchr(save, '/'))) {
            memcpy(pm->pathname, token, strlen(token));
            if (strstr(pm->pathname, ".so") || strstr(pm->pathname, ".so.")) {
                pm->filetype = PROCMAPS_FILETYPE_LIB;
            } else {
                struct stat statbuf;
                pm->filetype = PROCMAPS_FILETYPE_DATA;
                memset(&statbuf, 0, sizeof(statbuf));
                if (stat(pm->pathname, &statbuf) >= 0) {
                    ino_t inode1 = statbuf.st_ino;
                    memset(&statbuf, 0, sizeof(statbuf));
                    if (stat(appname, &statbuf) >= 0) {
                        if (statbuf.st_ino == inode1)
                            pm->filetype = PROCMAPS_FILETYPE_EXE;
                    }
                }
            }
        } else if ((token = strchr(save, '['))) {
            memcpy(pm->pathname, token, strlen(token));
            if (strstr(pm->pathname, "[heap]")) {
                pm->filetype = PROCMAPS_FILETYPE_HEAP;
            } else if (strstr(pm->pathname, "[stack]")) {
                pm->filetype = PROCMAPS_FILETYPE_STACK;
            } else if (strstr(pm->pathname, "[vdso]")) {
                pm->filetype = PROCMAPS_FILETYPE_VDSO;
            } else if (strstr(pm->pathname, "[vsyscall")) {
                pm->filetype = PROCMAPS_FILETYPE_SYSCALL;
            } else {
				if (verbose > 2)
	                fprintf(stderr, "[%s:%d] Unknown memory map: %s\n",
							__func__, __LINE__, pm->pathname);
                pm->filetype = PROCMAPS_FILETYPE_UNKNOWN;
            }
        } else {
            memcpy(pm->pathname, token, strlen(token));
            pm->filetype = PROCMAPS_FILETYPE_UNKNOWN;
        }
    } while (0);
    return 0;
}

struct ld_procmaps *ld_load_maps(pid_t pid, int verbose, size_t *num)
{
	char filename[OS_MAX_BUFFER];
	char appname[OS_MAX_BUFFER];
	FILE *ff = NULL;
    const size_t bufsz = 4096;
    char *buf = NULL;
	size_t mapmax = 0;
	size_t mapnum = 0;
	struct ld_procmaps *maps = NULL;
	if (pid == 0) {
		LOG_ERROR_INVALID_PID(pid);
		return NULL;
	}
	snprintf(filename, OS_MAX_BUFFER, "/proc/%d/maps", pid);
	snprintf(appname, OS_MAX_BUFFER, "/proc/%d/exe", pid);
	if (verbose > 2) {
		fprintf(stderr, "[%s:%d] Using Proc Maps from %s\n", __func__,
				__LINE__, filename);
		fprintf(stderr, "[%s:%d] Using Proc Exe from %s\n", __func__,
				__LINE__, appname);
	}
	do {
		buf = calloc(sizeof(char), bufsz);
		if (!buf) {
			LOG_ERROR_OUT_OF_MEMORY;
			break;
		}
		ff = fopen(filename, "r");
		if (!ff) {
			LOG_ERROR_FILE_OPEN(filename);
			break;
		}
		while (fgets(buf, bufsz, ff))
			mapmax++;
		if (verbose > 0)
			fprintf(stderr, "[%s:%d] Max number of mappings present: %ld\n",
					__func__, __LINE__, mapmax);
		fseek(ff, 0L, SEEK_SET);
		maps = calloc(sizeof(*maps), mapmax);
		if (!maps) {
			LOG_ERROR_OUT_OF_MEMORY;
			break;
		}
		if (verbose > 1)
			fprintf(stderr,
					"[%s:%d] Allocated memory to load proc maps.\n",
					__func__, __LINE__);
		memset(buf, 0, bufsz);
		mapnum = 0;
		while (fgets(buf, bufsz, ff)) {
			struct ld_procmaps *pm = &maps[mapnum];
			if (verbose > 3)
				fprintf(stderr, "[%s:%d] Parsing %s\n", __func__, __LINE__,
						buf);
			if (ld_procmaps_parse(buf, bufsz, pm, appname, verbose) < 0) {
				if (verbose > 1) {
					fprintf(stderr, "[%s:%d] Parsing failure. Ignoring.\n",
							__func__, __LINE__);
				}
				continue;
			}
			if (verbose > 4)
				ld_procmaps_dump(pm);
			mapnum++;
		}
		if (num)
			*num = mapnum;
		else
			if (verbose > 3)
				fprintf(stderr, "[%s:%d] Cannot return size of maps object.\n",
						__func__, __LINE__);
	} while (0);
	if (buf)
	    free(buf);
	if (ff)
	    fclose(ff);
	return maps;
}

void ld_free_maps(struct ld_procmaps *maps, size_t num)
{
	if (maps && num > 0) {
		size_t idx;
		for (idx = 0; idx < num; ++idx) {
			if (maps[idx].pathname)
				free(maps[idx].pathname);
			maps[idx].pathname = NULL;
		}
		free(maps);
		maps = NULL;
	}
}
