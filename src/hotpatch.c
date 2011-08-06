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
#include <hotpatch_config.h>
#include <hotpatch.h>

#define OS_MAX_BUFFER 512
#define LOG_ERROR_INVALID_PID(A) do { \
	fprintf(stderr, "[%s:%d] Invalid PID: %d\n", __func__, __LINE__, A); \
} while (0)
#define LOG_ERROR_OUT_OF_MEMORY do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] Out of memory. Error: %s\n", __func__, __LINE__, strerror(err)); \
} while (0)
#define LOG_ERROR_FILE_OPEN(FF) do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File(%s) open error. Error: %s\n", __func__, __LINE__, FF, strerror(err)); \
} while (0)
#define LOG_ERROR_FILE_SEEK do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File seek error. Error: %s\n", __func__, __LINE__, strerror(err)); \
} while (0)
#define LOG_ERROR_FILE_READ do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File read error. Error: %s\n", __func__, __LINE__, strerror(err)); \
} while (0)
#define LOG_ERROR_UNSUPPORTED_PROCESSOR do { \
	fprintf(stderr, \
	"[%s:%d] Only 32/64-bit Intel X86/X86-64 processors are supported.\n", __func__, __LINE__); \
} while (0)
#define LOG_INFO_HEADERS_LOADED do { \
	fprintf(stderr, "[%s:%d] Exe headers loaded.\n", __func__, __LINE__); \
} while (0)

struct hotpatch_is_opaque {
	pid_t pid;
	enum {
		HOTPATCH_EXE_IS_NEITHER,
		HOTPATCH_EXE_IS_32BIT,
		HOTPATCH_EXE_IS_64BIT
	} is64;
	int fd_exe;
	void *proghdrs; /* program headers */
	size_t proghdrnum;
	size_t proghdrsize; /* total buffer size */
	void *sechdrs; /* section headers */
	size_t sechdrnum;
	size_t sechdrsize; /* total buffer size */
	size_t secnametblidx;
	char *exepath;
	int inserted;
};

static int exe_open_file(pid_t pid)
{
	int fd = -1;
	if (pid > 0) {
		char buf[OS_MAX_BUFFER];
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			LOG_ERROR_FILE_OPEN(buf);
		}
	}
	return fd;
}

static int exe_elf_identify(unsigned char *e_ident, size_t size)
{
	if (e_ident && size > 0) {
		if ((e_ident[EI_MAG0] == ELFMAG0) &&
			(e_ident[EI_MAG1] == ELFMAG1) &&
			(e_ident[EI_MAG2] == ELFMAG2) &&
			(e_ident[EI_MAG3] == ELFMAG3)) {
			int is64 = HOTPATCH_EXE_IS_NEITHER;
			/* magic number says this is an ELF file */
			switch (e_ident[EI_CLASS]) {
			case ELFCLASS32:
				is64 = HOTPATCH_EXE_IS_32BIT;
				break;
			case ELFCLASS64:
				is64 = HOTPATCH_EXE_IS_64BIT;
				break;
			case ELFCLASSNONE:
			default:
				is64 = HOTPATCH_EXE_IS_NEITHER;
				break;
			}
			if (is64 != HOTPATCH_EXE_IS_NEITHER) {
				int isbigendian = -1;
				int iscurrent = 0;
				int islinux = 0;
				switch (e_ident[EI_DATA]) {
				case ELFDATA2LSB:
					isbigendian = 0;
					break;
				case ELFDATA2MSB:
					isbigendian = 1;
					break;
				case ELFDATANONE:
				default:
					isbigendian = -1;
					break;
				}
				if (e_ident[EI_VERSION] == EV_CURRENT) {
					iscurrent = 1;
				}
				if (e_ident[EI_OSABI] == ELFOSABI_LINUX) {
					islinux = 1;
				}
				if (islinux && isbigendian == 0 && iscurrent) {
					return is64;
				}
			}
		}
	}
	return HOTPATCH_EXE_IS_NEITHER;
}


static int exe_load_headers(hotpatch_t *hp)
{
	Elf32_Ehdr hdr32;
	Elf64_Ehdr hdr64;
	off_t shdroffset = 0;
	off_t phdroffset = 0;
	int fd = -1;
	if (!hp) {
		return -1;
	}
	fd = hp->fd_exe;
	memset(&hdr32, 0, sizeof(hdr32));
	if (lseek(fd, 0, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(fd, &hdr32, sizeof(hdr32)) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	hp->is64 = exe_elf_identify(hdr32.e_ident, EI_NIDENT);
	switch (hp->is64) {
	case HOTPATCH_EXE_IS_32BIT:
		if (hdr32.e_machine != EM_386) {
			LOG_ERROR_UNSUPPORTED_PROCESSOR;
			return -1;
		}
		if (hdr32.e_shoff > 0) {
			shdroffset = 0 + hdr32.e_shoff;
			hp->sechdrnum = 0 + hdr32.e_shnum;
			hp->sechdrsize = 0 + hdr32.e_shnum * hdr32.e_shentsize;
			hp->secnametblidx = 0 + hdr32.e_shstrndx;
		}
		if (hdr32.e_phoff > 0) {
			phdroffset = 0 + hdr32.e_phoff;
			hp->proghdrnum = 0 + hdr32.e_phnum;
			hp->proghdrsize = 0 + hdr32.e_phnum * hdr32.e_phentsize;
		}
		break;
	case HOTPATCH_EXE_IS_64BIT:
		memset(&hdr64, 0, sizeof(hdr64));
		if (lseek(fd, 0, SEEK_SET) < 0) {
			LOG_ERROR_FILE_SEEK;
			return -1;
		}
		if (read(fd, &hdr64, sizeof(hdr64)) < 0) {
			LOG_ERROR_FILE_READ;
			return -1;
		}
		if (hdr64.e_machine != EM_X86_64) {
			LOG_ERROR_UNSUPPORTED_PROCESSOR;
			return -1;
		}
		if (hdr64.e_shoff > 0) {
			shdroffset = 0 + hdr64.e_shoff;
			hp->sechdrnum = 0 + hdr64.e_shnum;
			hp->sechdrsize = 0 + hdr64.e_shnum * hdr64.e_shentsize;
			hp->secnametblidx = 0 + hdr64.e_shstrndx;
		}
		if (hdr64.e_phoff > 0) {
			phdroffset = 0 + hdr64.e_phoff;
			hp->proghdrnum = 0 + hdr64.e_phnum;
			hp->proghdrsize = 0 + hdr64.e_phnum * hdr64.e_phentsize;
		}
		break;
	case HOTPATCH_EXE_IS_NEITHER:
	default:
		return -1;
	}
	if (shdroffset > 0 && hp->sechdrsize > 0) {
		hp->sechdrs = malloc(hp->sechdrsize);
		if (!hp->sechdrs) {
			LOG_ERROR_OUT_OF_MEMORY;
			return -1;
		}
		memset(hp->sechdrs, 0, hp->sechdrsize);
		if (lseek(fd, shdroffset, SEEK_SET) < 0) {
			LOG_ERROR_FILE_SEEK;
			return -1;
		}
		if (read(fd, hp->sechdrs, hp->sechdrsize) < 0) {
			LOG_ERROR_FILE_READ;
			return -1;
		}
		/* copy section string table over.
		// read section names in
		// check for symbol tables and string tables
		// copy the string tables in
        */
	}
	if (phdroffset > 0 && hp->proghdrsize > 0) {
		hp->proghdrs = malloc(hp->proghdrsize);
		if (!hp->proghdrs) {
			LOG_ERROR_OUT_OF_MEMORY;
			return -1;
		}
		memset(hp->proghdrs, 0, hp->proghdrsize);
		if (lseek(fd, phdroffset, SEEK_SET) < 0) {
			LOG_ERROR_FILE_SEEK;
			return -1;
		}
		if (read(fd, hp->proghdrs, hp->proghdrsize) < 0) {
			LOG_ERROR_FILE_READ;
			return -1;
		}
	}
	return 0;
}

static int exe_get_symboltable(hotpatch_t *hp)
{
	Elf32_Shdr *shdr32 = NULL;
	Elf64_Shdr *shdr64 = NULL;
	if (!hp || !hp->sechdrs) {
		return -1;
	}
	switch(hp->is64) {
	size_t idx = 0;
	case HOTPATCH_EXE_IS_32BIT:
		shdr32 = (Elf32_Shdr *)hp->sechdrs;
		for (idx = 0; idx < hp->sechdrnum; ++idx) {
			if (shdr32[idx].sh_type == SHT_SYMTAB) {
			}
		}
		break;
	case HOTPATCH_EXE_IS_64BIT:
		shdr64 = (Elf64_Shdr *)hp->sechdrs;
		for (idx = 0; idx < hp->sechdrnum; ++idx) {

		}
		break;
	case HOTPATCH_EXE_IS_NEITHER:
	default:
		return -1;
	}
	return 0;
}

hotpatch_t *hotpatch_create(pid_t pid)
{
	hotpatch_t *hp = NULL;
	if (pid > 0) {
		hp = malloc(sizeof(*hp));
		if (hp) {
			memset(hp, 0, sizeof(*hp));
			hp->pid = pid;
			hp->is64 = HOTPATCH_EXE_IS_NEITHER;
			hp->fd_exe = exe_open_file(hp->pid);
			if (hp->fd_exe > 0) {
				if (exe_load_headers(hp) >= 0) {
					LOG_INFO_HEADERS_LOADED;
				}
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
		if (hp->fd_exe > 0) {
			close(hp->fd_exe);
			hp->fd_exe = -1;
		}
		if (hp->sechdrs) {
			free(hp->sechdrs);
			hp->sechdrs = NULL;
		}
		if (hp->proghdrs) {
			free(hp->proghdrs);
			hp->proghdrs = NULL;
		}
		free(hp);
		hp = NULL;
	}
}

ptr32or64_t *hotpatch_read_symbol(hotpatch_t *hp, const char *symbol)
{
	ptr32or64_t *ptr = NULL;
	if (!hp || !symbol) {
		return NULL;
	}
	exe_get_symboltable(hp);
	return ptr;
}

int hotpatch_insert(hotpatch_t *hp, const char *dll, const char *symbol,
				void *arg)
{
	if (!hp) {
		return -1;
	}
	return 0;
}
