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
#define LOG_INFO_HEADERS_LOADED(verbose) do { \
	if (verbose > 2) \
		fprintf(stderr, "[%s:%d] Exe headers loaded.\n", __func__, __LINE__); \
} while (0)

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
	char *strsymtbl; /* string table for symbol names */
	size_t strsymtbl_size;
	char *exepath;
	struct hotpatch_symbol {
		char *name; /* null terminated symbol name */
		void *address; /* address at which it is available */
	} *symbols;
	size_t symbols_num;
	int inserted;
};

/* each of the exe_* functions have to be reentrant and thread-safe */
static int exe_open_file(pid_t pid, int verbose)
{
	int fd = -1;
	if (pid > 0) {
		char buf[OS_MAX_BUFFER];
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		if (verbose > 3)
			fprintf(stderr, "[%s:%d] Exe symlink for pid %d : %s\n", __func__,
					__LINE__, pid, buf);
		fd = open(buf, O_RDONLY);
		if (fd < 0)
			LOG_ERROR_FILE_OPEN(buf);
		if (verbose > 3)
			fprintf(stderr, "[%s:%d] Exe file descriptor: %d\n", __func__,
					__LINE__, fd);
	} else {
		if (verbose > 1)
			fprintf(stderr, "[%s:%d] Pid %d has no valid file descriptor.\n",
					__func__, __LINE__, pid);
	}
	return fd;
}

static int exe_elf_identify(unsigned char *e_ident, size_t size, int verbose)
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
				if (verbose > 3)
					fprintf(stderr, "[%s:%d] File is 32-bit ELF\n", __func__,
							__LINE__);
				break;
			case ELFCLASS64:
				is64 = HOTPATCH_EXE_IS_64BIT;
				if (verbose > 3)
					fprintf(stderr, "[%s:%d] File is 64-bit ELF\n", __func__,
							__LINE__);
				break;
			case ELFCLASSNONE:
			default:
				is64 = HOTPATCH_EXE_IS_NEITHER;
				if (verbose > 3)
					fprintf(stderr, "[%s:%d] File is unsupported ELF\n",
							__func__, __LINE__);
				break;
			}
			if (is64 != HOTPATCH_EXE_IS_NEITHER) {
				int isbigendian = -1;
				int iscurrent = 0;
				int islinux = 0;
				switch (e_ident[EI_DATA]) {
				case ELFDATA2LSB:
					isbigendian = 0;
					if (verbose > 3)
						fprintf(stderr, "[%s:%d] Little endian format.\n",
								__func__, __LINE__);
					break;
				case ELFDATA2MSB:
					isbigendian = 1;
					if (verbose > 3)
						fprintf(stderr, "[%s:%d] Big endian format.\n",
								__func__, __LINE__);
					break;
				case ELFDATANONE:
				default:
					isbigendian = -1;
					if (verbose > 2)
						fprintf(stderr, "[%s:%d] Unknown endian format.\n",
								__func__, __LINE__);
					break;
				}
				if (e_ident[EI_VERSION] == EV_CURRENT) {
					iscurrent = 1;
					if (verbose > 3)
						fprintf(stderr, "[%s:%d] Current ELF format.\n",
								__func__, __LINE__);
				}
				if (verbose > 3)
					fprintf(stderr, "[%s:%d] ELFOSABI: %d\n", __func__,
							__LINE__, e_ident[EI_OSABI]);
				if (e_ident[EI_OSABI] == ELFOSABI_LINUX ||
					e_ident[EI_OSABI] == ELFOSABI_SYSV) {
					islinux = 1;
					if (verbose > 3)
						fprintf(stderr, "[%s:%d] OS ABI is Linux.\n", __func__,
								__LINE__);
				}
				if (islinux && isbigendian == 0 && iscurrent) {
					return is64;
				}
				if (verbose > 1)
					fprintf(stderr, "[%s:%d] Not an acceptable header.\n",
							__func__, __LINE__);
			}
		} else {
			if (verbose > 3)
				fprintf(stderr, "[%s:%d] This is not an ELF file format.\n",
						__func__, __LINE__);
		}
	}
	return HOTPATCH_EXE_IS_NEITHER;
}

static int exe_load_symbol_table(hotpatch_t *hp, Elf64_Shdr *symh,
								 Elf64_Shdr *strh)
{
	while (hp && symh && strh) {
		if (hp->verbose > 3)
			fprintf(stderr, "[%s:%d] Retrieving symbol table.\n", __func__,
					__LINE__);
		if (lseek(hp->fd_exe, strh->sh_offset, SEEK_SET) < 0) {
			LOG_ERROR_FILE_SEEK;
			break;
		}
		hp->strsymtbl_size = strh->sh_size + 0;
		hp->strsymtbl = malloc(strh->sh_size);
		if (!hp->strsymtbl) {
			LOG_ERROR_OUT_OF_MEMORY;
			break;
		}
		if (read(hp->fd_exe, hp->strsymtbl, strh->sh_size) < 0) {
			LOG_ERROR_FILE_READ;
			break;
		}
		if (symh->sh_entsize > 0 && symh->sh_size > 0) {
			size_t idx;
			size_t sym_num = symh->sh_size / symh->sh_entsize;
			Elf64_Sym *syms = malloc(symh->sh_size);
			if (!syms) {
				LOG_ERROR_OUT_OF_MEMORY;
				break;
			}
			if (lseek(hp->fd_exe, symh->sh_offset, SEEK_SET) < 0) {
				LOG_ERROR_FILE_SEEK;
				free(syms);
				break;
			}
			if (read(hp->fd_exe, syms, symh->sh_size) < 0) {
				LOG_ERROR_FILE_READ;
				free(syms);
				break;
			}
			hp->symbols_num = 0;
			hp->symbols = malloc(sym_num * sizeof(*hp->symbols));
			if (!hp->symbols) {
				LOG_ERROR_OUT_OF_MEMORY;
			} else {
				memset(hp->symbols, 0, sizeof(*hp->symbols) * sym_num);
			}
			for (idx = 0; idx < sym_num; ++idx) {
				const char *name = syms[idx].st_name > 0 ?
					&hp->strsymtbl[syms[idx].st_name] : NULL;
				if (name) {
					if (hp->verbose > 1)
						fprintf(stderr, "[%s:%d] Symbol %ld is %s at %p\n",
							__func__, __LINE__, idx, name,
							(void *)syms[idx].st_value);
					hp->symbols[hp->symbols_num].name = strdup(name);
					hp->symbols[hp->symbols_num].address = (void *)syms[idx].st_value;
					hp->symbols_num++;
				}
			}
			free(syms);
			return 0;
		}
	}
	return -1;
}

static int exe_load_section_headers(hotpatch_t *hp)
{
	Elf64_Shdr *strsectblhdr = NULL;
	Elf64_Shdr *sechdrs = NULL;
	size_t idx = 0;
	ssize_t symtab = -1;
	ssize_t strtab = -1;

	if (!hp || hp->sechdr_offset == 0 || hp->sechdr_size == 0)
		return -1;
	if (hp->verbose > 3)
		fprintf(stderr, "[%s:%d] Retrieving section headers.\n", __func__,
				__LINE__);
	hp->sechdrs = malloc(hp->sechdr_size);
	if (!hp->sechdrs) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	memset(hp->sechdrs, 0, hp->sechdr_size);
	if (hp->verbose > 3)
		fprintf(stderr, "[%s:%d] Reading section header offset at %ld\n",
				__func__, __LINE__, hp->sechdr_offset);
	if (lseek(hp->fd_exe, hp->sechdr_offset, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(hp->fd_exe, hp->sechdrs, hp->sechdr_size) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	sechdrs = (Elf64_Shdr *)hp->sechdrs;
	strsectblhdr = &sechdrs[hp->secnametbl_idx];
	if (lseek(hp->fd_exe, strsectblhdr->sh_offset, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	hp->strsectbl = malloc(strsectblhdr->sh_size);
	if (!hp->strsectbl) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	hp->strsectbl_size = strsectblhdr->sh_size + 0;
	if (read(hp->fd_exe, hp->strsectbl, strsectblhdr->sh_size) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	if (hp->verbose > 3)
		fprintf(stderr, "[%s:%d] Number of sections: %ld\n", __func__, __LINE__,
				hp->sechdr_num);
	for (idx = 0; idx < hp->sechdr_num; ++idx) {
		const char *name = &hp->strsectbl[sechdrs[idx].sh_name];
		if (name) {
			fprintf(stderr, "[%s:%d] Section name: %s Addr: %p Len: %ld\n",
					__func__, __LINE__, name, (void *)sechdrs[idx].sh_offset,
					sechdrs[idx].sh_size);
		} else {
			fprintf(stderr, "[%s:%d] Section name: %s Addr: %p Len: %ld\n",
					__func__, __LINE__, "N/A", (void *)sechdrs[idx].sh_offset,
					sechdrs[idx].sh_size);
		}
		switch (sechdrs[idx].sh_type) {
		case SHT_SYMTAB:
			symtab = idx;
			if (hp->verbose > 3)
				fprintf(stderr, "[%s:%d] Symbol table offset: %ld size: %ld "
						"entsize: %ld entries: %ld\n",
				__func__, __LINE__, sechdrs[idx].sh_offset,
				sechdrs[idx].sh_size, sechdrs[idx].sh_entsize,
				sechdrs[idx].sh_size / sechdrs[idx].sh_entsize);
			break;
		case SHT_STRTAB:
			if (idx != hp->secnametbl_idx) {
				strtab = idx;
				if (hp->verbose > 2)
					fprintf(stderr, "[%s:%d] Reading symbol table from %s\n",
							__func__, __LINE__, name);
				/*TODO: take care of multiple string tables*/
				if (symtab >= 0 && exe_load_symbol_table(hp, &sechdrs[symtab],
							&sechdrs[strtab]) < 0) {
					fprintf(stderr, "[%s:%d] Failed to retrieve symbol "
							"table.\n", __func__, __LINE__);
				}
			}
			break;
		default:
			break;
		}
	}
	return 0;
}

static int exe_load_program_headers(hotpatch_t *hp)
{
	Elf64_Phdr *proghdrs = NULL;
	size_t idx = 0;
	if (!hp || hp->proghdr_offset == 0 || hp->proghdr_size == 0)
		return -1;
	hp->proghdrs = malloc(hp->proghdr_size);
	if (!hp->proghdrs) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	memset(hp->proghdrs, 0, hp->proghdr_size);
	if (lseek(hp->fd_exe, hp->proghdr_offset, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(hp->fd_exe, hp->proghdrs, hp->proghdr_size) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	if (hp->verbose > 3)
		fprintf(stderr, "[%s:%d] Number of segments: %ld\n", __func__, __LINE__,
				hp->proghdr_num);
	proghdrs = (Elf64_Phdr *)hp->proghdrs;
	for (idx = 0; idx < hp->proghdr_num; ++idx) {
		fprintf(stderr,
				"[%s:%d] Prog-header %ld: Type: %d VAddr: %p FileSz: %ld MemSz: %ld\n",
				__func__, __LINE__, idx, proghdrs[idx].p_type, (void *)proghdrs[idx].p_vaddr,
				proghdrs[idx].p_filesz, proghdrs[idx].p_memsz);
	}
	return 0;
}

static int exe_load_headers(hotpatch_t *hp)
{
	Elf64_Ehdr hdr;
	int fd = -1;
	if (!hp) {
		return -1;
	}
	fd = hp->fd_exe;
	memset(&hdr, 0, sizeof(hdr));
	if (lseek(fd, 0, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(fd, &hdr, sizeof(hdr)) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	if (hp->verbose > 3)
		fprintf(stderr, "[%s:%d] Reading Elf64 header.\n", __func__, __LINE__);
	hp->is64 = exe_elf_identify(hdr.e_ident, EI_NIDENT, hp->verbose);
	switch (hp->is64) {
	case HOTPATCH_EXE_IS_64BIT:
		if (hp->verbose > 3)
			fprintf(stderr, "[%s:%d] 64-bit valid exe\n", __func__, __LINE__);
		fprintf(stderr, "[%s:%d] Entry point %p\n", __func__, __LINE__,
				(void *)hdr.e_entry);
		if (hdr.e_machine != EM_X86_64) {
			LOG_ERROR_UNSUPPORTED_PROCESSOR;
			return -1;
		}
		if (hdr.e_shoff > 0) {
			hp->sechdr_offset = 0 + hdr.e_shoff;
			hp->sechdr_num = 0 + hdr.e_shnum;
			hp->sechdr_size = 0 + hdr.e_shnum * hdr.e_shentsize;
			hp->secnametbl_idx = 0 + hdr.e_shstrndx;
		}
		if (hdr.e_phoff > 0) {
			hp->proghdr_offset = 0 + hdr.e_phoff;
			hp->proghdr_num = 0 + hdr.e_phnum;
			hp->proghdr_size = 0 + hdr.e_phnum * hdr.e_phentsize;
		}
		break;
	case HOTPATCH_EXE_IS_32BIT:
	case HOTPATCH_EXE_IS_NEITHER:
	default:
		return -1;
	}
	if (exe_load_section_headers(hp) < 0) {
		fprintf(stderr, "[%s:%d] Error in loading section headers\n",
				__func__, __LINE__);
		return -1;
	}
	if (exe_load_program_headers(hp) < 0) {
		fprintf(stderr, "[%s:%d] Error in loading section headers\n",
				__func__, __LINE__);
		return -1;
	}
	return 0;
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
		hp->strsymtbl_size = 0;
		if (hp->strsymtbl) {
			free(hp->strsymtbl);
			hp->strsymtbl = NULL;
		}
		hp->strsectbl_size = 0;
		if (hp->strsectbl) {
			free(hp->strsectbl);
			hp->strsectbl = NULL;
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

void *hotpatch_read_symbol(hotpatch_t *hp, const char *symbol)
{
	void *ptr = NULL;
	size_t idx = 0;
	if (!hp || !symbol || !hp->symbols) {
		if (hp->verbose > 2)
			fprintf(stderr, "[%s:%d] Invalid arguments.\n", __func__, __LINE__);
		return NULL;
	}
	for (idx = 0; idx < hp->symbols_num; ++idx) {
		const char *name = hp->symbols[idx].name;
		if (strcmp(name, symbol) == 0) {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] Found %s in symbol list at %ld\n",
						__func__, __LINE__, symbol, idx);
			ptr = hp->symbols[idx].address;
			break;
		}
	}
	if (hp->verbose > 2)
		fprintf(stderr, "[%s:%d] Symbol %s has address %p\n", __func__,
				__LINE__, symbol, ptr);
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

size_t hotpatch_strnlen(const char *str, size_t maxlen)
{
    size_t len = 0;
    /* succinct code */
    if (str)
        while (len < maxlen && str[len++] != '\0');
    return len;
}
