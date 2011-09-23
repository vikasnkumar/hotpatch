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
#ifdef HOTPATCH_HAS_ASSERT_H
	#undef NDEBUG
	#include <assert.h>
#endif

enum {
    PERMS_NONE  = 0x0,
    PERMS_READ  = 0x1,
    PERMS_EXEC  = 0x2,
    PERMS_WRITE = 0x4,
    PERMS_PVT   = 0x8
};

enum {
    FILETYPE_UNKNOWN,
    FILETYPE_EXE,
    FILETYPE_LIB,
    FILETYPE_DATA,
    FILETYPE_VDSO,
    FILETYPE_HEAP,
    FILETYPE_STACK,
    FILETYPE_SYSCALL
};

struct procmaps {
    intptr_t addr_begin;
    intptr_t addr_end;
    bool addr_invalid;
    int permissions;
    intptr_t offset;
    int device_major;
    int device_minor;
    size_t inode;
    char *pathname;
    size_t pathname_sz;
    int filetype;
};

void procmaps_dump(struct procmaps *pm)
{
    if (!pm)
        return;
    printf("Pathname: %s\n", pm->pathname ? pm->pathname : "Unknown");
    printf("Address Start: %lx End: %lx Invalid: %d Offset: %ld\n", pm->addr_begin,
            pm->addr_end, pm->addr_invalid, pm->offset);
    printf("Device Major: %d Minor: %d\n", pm->device_major, pm->device_minor);
    printf("Inode: %ld\n", pm->inode);
    printf("Permissions: Read(%d) Write(%d) Execute(%d) Private(%d)\n",
            (pm->permissions & PERMS_READ) ? 1 : 0,
            (pm->permissions & PERMS_WRITE) ? 1 : 0,
            (pm->permissions & PERMS_EXEC) ? 1 : 0,
            (pm->permissions & PERMS_PVT) ? 1 : 0);
    printf("Pathname length: %ld\n", pm->pathname_sz);
    printf("Filetype: %d\n", pm->filetype);
}

int parse_buffer(char *buf, size_t bufsz, struct procmaps *pm,
                 const char *appname)
{
    if (!buf || !pm)
        return -1;
    /* this is hardcoded parsing of the maps file */
    do {
        char *token = NULL;
        char *save = NULL;
        int idx;
        memset(pm, 0, sizeof(*pm));
        token = strtok_r(buf, "-", &save);
        if (!token) break;
        pm->addr_begin = (intptr_t)strtol(token, NULL, 16);
        pm->addr_invalid = (errno == ERANGE) ? true : false;
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->addr_end = (intptr_t)strtol(token, NULL, 16);
        pm->addr_invalid = (errno == ERANGE) ? true : false;
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->permissions = PERMS_NONE;
        for (idx = strlen(token) - 1; idx >= 0; --idx) {
            switch (token[idx]) {
            case 'r':
                pm->permissions |= PERMS_READ;
                break;
            case 'w':
                pm->permissions |= PERMS_WRITE;
                break;
            case 'x':
                pm->permissions |= PERMS_EXEC;
                break;
            case 'p':
                pm->permissions |= PERMS_PVT;
                break;
            case '-':
                break;
            default:
                printf("Unknown flag: %c\n", token[idx]);
                break;
            }
        }
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->offset = (intptr_t)strtol(token, NULL, 16);
        if (errno == ERANGE) {
            pm->addr_begin = (intptr_t)strtoll(token, NULL, 16);
        }
        token = strtok_r(NULL, ":", &save);
        if (!token) break;
        pm->device_major = (int)strtol(token, NULL, 10);
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->device_minor = (int)strtol(token, NULL, 10);
        token = strtok_r(NULL, " ", &save);
        if (!token) break;
        pm->inode = (size_t)strtol(token, NULL, 10);
        token = strtok_r(NULL, "\n", &save);
        if (!token) break;
        pm->pathname_sz = strlen(token);
        pm->pathname = calloc(sizeof(char), pm->pathname_sz + 1);
        if (!pm->pathname) {
            printf("Out of memory.\n");
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
                pm->filetype = FILETYPE_LIB;
            } else {
                struct stat statbuf;
                pm->filetype = FILETYPE_DATA;
                memset(&statbuf, 0, sizeof(statbuf));
                if (stat(pm->pathname, &statbuf) >= 0) {
                    ino_t inode1 = statbuf.st_ino;
                    memset(&statbuf, 0, sizeof(statbuf));
                    if (stat(appname, &statbuf) >= 0) {
                        if (statbuf.st_ino == inode1)
                            pm->filetype = FILETYPE_EXE;
                    }
                }
            }
        } else if ((token = strchr(save, '['))) {
            memcpy(pm->pathname, token, strlen(token));
            if (strstr(pm->pathname, "[heap]")) {
                pm->filetype = FILETYPE_HEAP;
            } else if (strstr(pm->pathname, "[stack]")) {
                pm->filetype = FILETYPE_STACK;
            } else if (strstr(pm->pathname, "[vdso]")) {
                pm->filetype = FILETYPE_VDSO;
            } else if (strstr(pm->pathname, "[vsyscall")) {
                pm->filetype = FILETYPE_SYSCALL;
            } else {
                printf("Unknown memory map: %s\n", pm->pathname);
                pm->filetype = FILETYPE_UNKNOWN;
            }
        } else {
            memcpy(pm->pathname, token, strlen(token));
            pm->filetype = FILETYPE_UNKNOWN;
        }
    } while (0);
    return 0;
}

int main(int argc, char **argv)
{
    const size_t bufsz = 4096;
    char *buf = NULL;
    char filename[256];
    char appname[256];
    FILE *ff;
    pid_t pid = argc > 1 ? (pid_t)strtol(argv[1], NULL, 10) : getpid();
    if (pid == 0) {
        printf("Invalid pid.\n");
        return -1;
    }
    snprintf(filename, 256, "/proc/%d/maps", pid);
    snprintf(appname, 256, "/proc/%d/exe", pid);
    printf("Opening %s\n", filename);
    ff = fopen(filename, "r");
    if (!ff) {
        printf("Unable to open %s\n", filename);
        return -1;
    }
    buf = malloc(bufsz);
    if (!buf) {
        printf("[%s:%d] Out of memory\n", __func__, __LINE__);
        return -1;
    }
    while (fgets(buf, bufsz, ff)) {
        struct procmaps pm = { 0 };
        printf("%s\n", buf);
        parse_buffer(buf, bufsz, &pm, appname);
        procmaps_dump(&pm);
    }
    free(buf);
    fclose(ff);
    return 0;
}

