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

enum {
	HOTPATCH_SYMBOL_TYPE,
	HOTPATCH_UNKNOWN
};

static int exe_to_hotpatch_type(int info, int group)
{
	if (group == HOTPATCH_SYMBOL_TYPE) {
		int value = ELF64_ST_TYPE(info);
		if (value == STT_FUNC)
			return HOTPATCH_SYMBOL_IS_FUNCTION;
		else if (value == STT_FILE)
			return HOTPATCH_SYMBOL_IS_FILENAME;
		else if (value == STT_SECTION)
			return HOTPATCH_SYMBOL_IS_SECTION;
		else if (value == STT_OBJECT)
			return HOTPATCH_SYMBOL_IS_OBJECT;
		else
			return HOTPATCH_SYMBOL_IS_UNKNOWN;
	}
	return -1;
}

/* each of the exe_* functions have to be reentrant and thread-safe */
int exe_open_file(pid_t pid, int verbose)
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
	char *strsymtbl = NULL;
	size_t strsymtbl_size = 0;
	while (hp && symh && strh) {
		if (hp->verbose > 3)
			fprintf(stderr, "[%s:%d] Retrieving symbol table.\n", __func__,
					__LINE__);
		if (lseek(hp->fd_exe, strh->sh_offset, SEEK_SET) < 0) {
			LOG_ERROR_FILE_SEEK;
			break;
		}
		strsymtbl_size = strh->sh_size + 0;
		strsymtbl = malloc(strh->sh_size);
		if (!strsymtbl) {
			LOG_ERROR_OUT_OF_MEMORY;
			break;
		}
		if (read(hp->fd_exe, strsymtbl, strh->sh_size) < 0) {
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
			/* there might already exist symbols from another section.
			 * hence using realloc() takes care of that.
			 * */
			hp->symbols = realloc(hp->symbols,
								  (sym_num + hp->symbols_num) *
								  sizeof(*hp->symbols));
			if (!hp->symbols) {
				LOG_ERROR_OUT_OF_MEMORY;
				break;
			}
			memset(&hp->symbols[hp->symbols_num], 0, sizeof(*hp->symbols) * sym_num);
			/* index 0 is always NULL */
			for (idx = 1; idx < sym_num; ++idx) {
				const char *name = syms[idx].st_name > 0 ?
					&strsymtbl[syms[idx].st_name] : "";
				if (name) {
					char *name2;
					int symtype = exe_to_hotpatch_type(syms[idx].st_info,
									HOTPATCH_SYMBOL_TYPE);
					if (hp->verbose > 1)
						fprintf(stderr,
							"[%s:%d] Symbol %ld is %s at %p type %d size %ld\n",
							__func__, __LINE__, idx, name,
							(void *)syms[idx].st_value, symtype,
							syms[idx].st_size);
					name2 = strdup(name);
					if (!name2) {
						LOG_ERROR_OUT_OF_MEMORY;
						continue;
					}
					hp->symbols[hp->symbols_num].name = name2;
					hp->symbols[hp->symbols_num].address = (uintptr_t)syms[idx].st_value;
					hp->symbols[hp->symbols_num].size = (size_t)syms[idx].st_size;
					hp->symbols[hp->symbols_num].type = symtype;
					hp->symbols_num++;
				}
			}
			free(syms);
			if (strsymtbl)
				free(strsymtbl);
			return 0;
		}
	}
	if (strsymtbl)
		free(strsymtbl);
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
		if (hp->verbose > 0) {
			if (name)
				fprintf(stderr, "[%s:%d] Section name: %s Addr: %p Len: %ld\n",
						__func__, __LINE__, name, (void *)sechdrs[idx].sh_offset,
						sechdrs[idx].sh_size);
			else
				fprintf(stderr, "[%s:%d] Section name: %s Addr: %p Len: %ld\n",
						__func__, __LINE__, "N/A", (void *)sechdrs[idx].sh_offset,
						sechdrs[idx].sh_size);
		}
		switch (sechdrs[idx].sh_type) {
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			symtab = idx;
			if (hp->verbose > 3)
				fprintf(stderr, "[%s:%d] Symbol table offset: %ld size: %ld "
						"entsize: %ld entries: %ld\n",
				__func__, __LINE__, sechdrs[idx].sh_offset,
				sechdrs[idx].sh_size, sechdrs[idx].sh_entsize,
				(sechdrs[idx].sh_entsize > 0 ? sechdrs[idx].sh_size / sechdrs[idx].sh_entsize : 0));
			break;
		case SHT_STRTAB:
			if (idx != hp->secnametbl_idx) {
				strtab = idx;
				if (hp->verbose > 2)
					fprintf(stderr, "[%s:%d] Reading symbol table from %s\n",
							__func__, __LINE__, name);
				if (symtab >= 0 && exe_load_symbol_table(hp, &sechdrs[symtab],
							&sechdrs[strtab]) < 0) {
					fprintf(stderr, "[%s:%d] Failed to retrieve symbol "
							"table.\n", __func__, __LINE__);
				}
				symtab = -1;
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
	int rc = 0;
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
		rc = 0;
		if (hp->verbose > 2) {
			fprintf(stderr,
					"[%s:%d] Prog-header %ld: Type: %d "
					"VAddr: %p PAddr: %p FileSz: %ld MemSz: %ld\n",
					__func__, __LINE__, idx, proghdrs[idx].p_type,
					(void *)proghdrs[idx].p_vaddr,
					(void *)proghdrs[idx].p_paddr,
					proghdrs[idx].p_filesz, proghdrs[idx].p_memsz);
		}
		if (proghdrs[idx].p_type == PT_INTERP) {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] PT_INTERP section found\n", __func__,
					__LINE__);
			if (proghdrs[idx].p_filesz == 0)
				continue;
			if (lseek(hp->fd_exe, proghdrs[idx].p_offset, SEEK_SET) < 0) {
				LOG_ERROR_FILE_SEEK;
				rc = -1;
				break;
			}
			if (hp->interp.name) {
				free(hp->interp.name);
				memset(&hp->interp, 0, sizeof(hp->interp));
			}
			hp->interp.name = malloc(proghdrs[idx].p_filesz);
			if (!hp->interp.name) {
				LOG_ERROR_OUT_OF_MEMORY;
				rc = -1;
				break;
			}
			if (read(hp->fd_exe, hp->interp.name, proghdrs[idx].p_filesz) < 0) {
				LOG_ERROR_FILE_READ;
				rc = -1;
				break;
			}
			hp->interp.length = proghdrs[idx].p_filesz;
			hp->interp.ph_addr = proghdrs[idx].p_vaddr;
			if (hp->verbose > 0)
				fprintf(stderr, "[%s:%d] Found %s at V-Addr 0x%lx\n",
						__func__, __LINE__, hp->interp.name,
						hp->interp.ph_addr);
		} else if (proghdrs[idx].p_type == PT_DYNAMIC) {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] PT_DYNAMIC section found\n", __func__,
					__LINE__);
		} else if (proghdrs[idx].p_type == PT_LOAD) {
			if (hp->verbose > 1)
				fprintf(stderr, "[%s:%d] PT_LOAD section found\n", __func__,
					__LINE__);
		}
	}
	return rc;
}

int exe_load_headers(hotpatch_t *hp)
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
		if (hp->verbose > 0)
			fprintf(stderr, "[%s:%d] Entry point %p\n", __func__, __LINE__,
				(void *)hdr.e_entry);
		hp->entry_point = (uintptr_t)hdr.e_entry;
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
