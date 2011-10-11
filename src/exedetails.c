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

#if __WORDSIZE == 64
	typedef Elf64_Ehdr Elf_Ehdr;
	typedef Elf64_Phdr Elf_Phdr;
	typedef Elf64_Shdr Elf_Shdr;
	typedef Elf64_Sym Elf_Sym;
#else
	typedef Elf32_Ehdr Elf_Ehdr;
	typedef Elf32_Phdr Elf_Phdr;
	typedef Elf32_Shdr Elf_Shdr;
	typedef Elf32_Sym Elf_Sym;
#endif

enum {
	HOTPATCH_SYMBOL_TYPE,
	HOTPATCH_UNKNOWN
};

struct elf_internals {
	int fd;
	enum elf_bit is64;
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
	/*
	 * stored here temporarily, should not be freed unless on failure.
	 */
	uintptr_t entry_point;
	struct elf_symbol *symbols;
	size_t symbols_num;
	struct elf_interp interp;
};

/* each of the exe_* functions have to be reentrant and thread-safe */
static int exe_get_hotpatch_type(int info, int group)
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

static int exe_open_filename(const char *filename, int verbose)
{
	int fd = -1;
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		LOG_ERROR_FILE_OPEN(filename);
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Exe file descriptor: %d\n", __func__,
				__LINE__, fd);
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

static int exe_load_symbol_table(struct elf_internals *ei, Elf_Shdr *symh,
								 Elf_Shdr *strh, int verbose)
{
	char *strsymtbl = NULL;
	size_t strsymtbl_size = 0;
	while (ei && symh && strh) {
		if (verbose > 3)
			fprintf(stderr, "[%s:%d] Retrieving symbol table.\n", __func__,
					__LINE__);
		if (lseek(ei->fd, strh->sh_offset, SEEK_SET) < 0) {
			LOG_ERROR_FILE_SEEK;
			break;
		}
		strsymtbl_size = strh->sh_size + 0;
		strsymtbl = malloc(strh->sh_size);
		if (!strsymtbl) {
			LOG_ERROR_OUT_OF_MEMORY;
			break;
		}
		if (read(ei->fd, strsymtbl, strh->sh_size) < 0) {
			LOG_ERROR_FILE_READ;
			break;
		}
		if (symh->sh_entsize > 0 && symh->sh_size > 0) {
			size_t idx;
			size_t sym_num = symh->sh_size / symh->sh_entsize;
			Elf_Sym *syms = malloc(symh->sh_size);
			if (!syms) {
				LOG_ERROR_OUT_OF_MEMORY;
				break;
			}
			if (lseek(ei->fd, symh->sh_offset, SEEK_SET) < 0) {
				LOG_ERROR_FILE_SEEK;
				free(syms);
				break;
			}
			if (read(ei->fd, syms, symh->sh_size) < 0) {
				LOG_ERROR_FILE_READ;
				free(syms);
				break;
			}
			/* there might already exist symbols from another section.
			 * hence using realloc() takes care of that.
			 * */
			ei->symbols = realloc(ei->symbols,
								  (sym_num + ei->symbols_num) *
								  sizeof(*ei->symbols));
			if (!ei->symbols) {
				LOG_ERROR_OUT_OF_MEMORY;
				break;
			}
			memset(&ei->symbols[ei->symbols_num], 0, sizeof(*ei->symbols) * sym_num);
			/* index 0 is always NULL */
			for (idx = 1; idx < sym_num; ++idx) {
				const char *name = syms[idx].st_name > 0 ?
					&strsymtbl[syms[idx].st_name] : "";
				if (name) {
					char *name2;
					int symtype = exe_get_hotpatch_type(syms[idx].st_info,
									HOTPATCH_SYMBOL_TYPE);
					if (verbose > 2)
						fprintf(stderr,
							"[%s:%d] Symbol "LU" is %s at %p type %d size "LU"\n",
							__func__, __LINE__, idx, name,
							(void *)syms[idx].st_value, symtype,
							syms[idx].st_size);
					name2 = strdup(name);
					if (!name2) {
						LOG_ERROR_OUT_OF_MEMORY;
						continue;
					}
					ei->symbols[ei->symbols_num].name = name2;
					ei->symbols[ei->symbols_num].address = (uintptr_t)syms[idx].st_value;
					ei->symbols[ei->symbols_num].size = (size_t)syms[idx].st_size;
					ei->symbols[ei->symbols_num].type = symtype;
					ei->symbols_num++;
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

static int exe_load_section_headers(struct elf_internals *ei, int verbose)
{
	Elf_Shdr *strsectblhdr = NULL;
	Elf_Shdr *sechdrs = NULL;
	size_t idx = 0;
	ssize_t symtab = -1;
	ssize_t strtab = -1;

	if (!ei || ei->sechdr_offset == 0 || ei->sechdr_size == 0)
		return -1;
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Retrieving section headers.\n", __func__,
				__LINE__);
	ei->sechdrs = malloc(ei->sechdr_size);
	if (!ei->sechdrs) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	memset(ei->sechdrs, 0, ei->sechdr_size);
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Reading section header offset at "LU"\n",
				__func__, __LINE__, (size_t)ei->sechdr_offset);
	if (lseek(ei->fd, ei->sechdr_offset, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(ei->fd, ei->sechdrs, ei->sechdr_size) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	sechdrs = (Elf_Shdr *)ei->sechdrs;
	strsectblhdr = &sechdrs[ei->secnametbl_idx];
	if (lseek(ei->fd, strsectblhdr->sh_offset, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	ei->strsectbl = malloc(strsectblhdr->sh_size);
	if (!ei->strsectbl) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	ei->strsectbl_size = strsectblhdr->sh_size + 0;
	if (read(ei->fd, ei->strsectbl, strsectblhdr->sh_size) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Number of sections: "LU"\n", __func__, __LINE__,
				ei->sechdr_num);
	for (idx = 0; idx < ei->sechdr_num; ++idx) {
		const char *name = &ei->strsectbl[sechdrs[idx].sh_name];
		if (verbose > 2) {
			if (name)
				fprintf(stderr, "[%s:%d] Section name: %s Addr: %p Len: "LU"\n",
						__func__, __LINE__, name, (void *)sechdrs[idx].sh_offset,
						sechdrs[idx].sh_size);
			else
				fprintf(stderr, "[%s:%d] Section name: %s Addr: %p Len: "LU"\n",
						__func__, __LINE__, "N/A", (void *)sechdrs[idx].sh_offset,
						sechdrs[idx].sh_size);
		}
		switch (sechdrs[idx].sh_type) {
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			symtab = idx;
			if (verbose > 3)
				fprintf(stderr, "[%s:%d] Symbol table offset: "LU" size: "LU" "
						"entsize: "LU" entries: "LU"\n",
				__func__, __LINE__, sechdrs[idx].sh_offset,
				sechdrs[idx].sh_size, sechdrs[idx].sh_entsize,
				(sechdrs[idx].sh_entsize > 0 ? sechdrs[idx].sh_size / sechdrs[idx].sh_entsize : 0));
			break;
		case SHT_STRTAB:
			if (idx != ei->secnametbl_idx) {
				strtab = idx;
				if (verbose > 2)
					fprintf(stderr, "[%s:%d] Reading symbol table from %s\n",
							__func__, __LINE__, name);
				if (symtab >= 0 && exe_load_symbol_table(ei, &sechdrs[symtab],
							&sechdrs[strtab], verbose) < 0) {
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

static int exe_load_program_headers(struct elf_internals *ei, int verbose)
{
	Elf_Phdr *proghdrs = NULL;
	size_t idx = 0;
	int rc = 0;
	if (!ei || ei->proghdr_offset == 0 || ei->proghdr_size == 0)
		return -1;
	ei->proghdrs = malloc(ei->proghdr_size);
	if (!ei->proghdrs) {
		LOG_ERROR_OUT_OF_MEMORY;
		return -1;
	}
	memset(ei->proghdrs, 0, ei->proghdr_size);
	if (lseek(ei->fd, ei->proghdr_offset, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(ei->fd, ei->proghdrs, ei->proghdr_size) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Number of segments: "LU"\n", __func__, __LINE__,
				ei->proghdr_num);
	proghdrs = (Elf_Phdr *)ei->proghdrs;
	for (idx = 0; idx < ei->proghdr_num; ++idx) {
		rc = 0;
		if (verbose > 2) {
			fprintf(stderr,
					"[%s:%d] Prog-header "LU": Type: %d "
					"VAddr: %p PAddr: %p FileSz: "LU" MemSz: "LU"\n",
					__func__, __LINE__, idx, proghdrs[idx].p_type,
					(void *)proghdrs[idx].p_vaddr,
					(void *)proghdrs[idx].p_paddr,
					proghdrs[idx].p_filesz, proghdrs[idx].p_memsz);
		}
		if (proghdrs[idx].p_type == PT_INTERP) {
			if (verbose > 1)
				fprintf(stderr, "[%s:%d] PT_INTERP section found\n", __func__,
					__LINE__);
			if (proghdrs[idx].p_filesz == 0)
				continue;
			if (lseek(ei->fd, proghdrs[idx].p_offset, SEEK_SET) < 0) {
				LOG_ERROR_FILE_SEEK;
				rc = -1;
				break;
			}
			if (ei->interp.name) {
				free(ei->interp.name);
				memset(&ei->interp, 0, sizeof(ei->interp));
			}
			ei->interp.name = malloc(proghdrs[idx].p_filesz);
			if (!ei->interp.name) {
				LOG_ERROR_OUT_OF_MEMORY;
				rc = -1;
				break;
			}
			if (read(ei->fd, ei->interp.name, proghdrs[idx].p_filesz) < 0) {
				LOG_ERROR_FILE_READ;
				rc = -1;
				break;
			}
			ei->interp.length = proghdrs[idx].p_filesz;
			ei->interp.ph_addr = proghdrs[idx].p_vaddr;
			if (verbose > 1)
				fprintf(stderr, "[%s:%d] Found %s at V-Addr 0x"LX"\n",
						__func__, __LINE__, ei->interp.name,
						ei->interp.ph_addr);
		} else if (proghdrs[idx].p_type == PT_DYNAMIC) {
			if (verbose > 1)
				fprintf(stderr, "[%s:%d] PT_DYNAMIC section found\n", __func__,
					__LINE__);
		} else if (proghdrs[idx].p_type == PT_LOAD) {
			if (verbose > 1)
				fprintf(stderr, "[%s:%d] PT_LOAD section found\n", __func__,
					__LINE__);
		}
	}
	return rc;
}

static int exe_load_headers(struct elf_internals *ei, int verbose)
{
	Elf_Ehdr hdr;
	int fd = -1;
	if (!ei) {
		return -1;
	}
	fd = ei->fd;
	memset(&hdr, 0, sizeof(hdr));
	if (lseek(fd, 0, SEEK_SET) < 0) {
		LOG_ERROR_FILE_SEEK;
		return -1;
	}
	if (read(fd, &hdr, sizeof(hdr)) < 0) {
		LOG_ERROR_FILE_READ;
		return -1;
	}
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Reading Elf header.\n", __func__, __LINE__);
	ei->is64 = exe_elf_identify(hdr.e_ident, EI_NIDENT, verbose);
	switch (ei->is64) {
	case HOTPATCH_EXE_IS_64BIT:
		if (verbose > 3)
			fprintf(stderr, "[%s:%d] 64-bit valid exe\n", __func__, __LINE__);
		break;
	case HOTPATCH_EXE_IS_32BIT:
		if (verbose > 3)
			fprintf(stderr, "[%s:%d] 32-bit valid exe\n", __func__, __LINE__);
		break;
	case HOTPATCH_EXE_IS_NEITHER:
	default:
		return -1;
	}
	if (verbose > 1)
		fprintf(stderr, "[%s:%d] Entry point %p\n", __func__, __LINE__,
				(void *)hdr.e_entry);
	ei->entry_point = (uintptr_t)hdr.e_entry;
	if (hdr.e_machine != EM_X86_64 && hdr.e_machine != EM_386) {
		LOG_ERROR_UNSUPPORTED_PROCESSOR;
		return -1;
	}
	if (hdr.e_shoff > 0) {
		ei->sechdr_offset = 0 + hdr.e_shoff;
		ei->sechdr_num = 0 + hdr.e_shnum;
		ei->sechdr_size = 0 + hdr.e_shnum * hdr.e_shentsize;
		ei->secnametbl_idx = 0 + hdr.e_shstrndx;
	}
	if (hdr.e_phoff > 0) {
		ei->proghdr_offset = 0 + hdr.e_phoff;
		ei->proghdr_num = 0 + hdr.e_phnum;
		ei->proghdr_size = 0 + hdr.e_phnum * hdr.e_phentsize;
	}
	if (exe_load_section_headers(ei, verbose) < 0) {
		fprintf(stderr, "[%s:%d] Error in loading section headers\n",
				__func__, __LINE__);
		return -1;
	}
	if (exe_load_program_headers(ei, verbose) < 0) {
		fprintf(stderr, "[%s:%d] Error in loading section headers\n",
				__func__, __LINE__);
		return -1;
	}
	return 0;
}

struct elf_symbol *exe_load_symbols(const char *filename, int verbose,
									 size_t *symbols_num,
									 uintptr_t *entry_point,
									 struct elf_interp *interp,
									 enum elf_bit *is64)
{
	int rc = 0;
	struct elf_symbol *symbols = NULL;
	struct elf_internals ei;
	memset(&ei, 0, sizeof(ei));
	if (entry_point)
		*entry_point = 0;
	ei.fd = exe_open_filename(filename, verbose);
	if (ei.fd < 0) {
		return NULL;
	}
	if ((rc = exe_load_headers(&ei, verbose)) < 0) {
		fprintf(stderr, "[%s:%d] Unable to load Elf details for %s\n",
				__func__, __LINE__, filename);
	}
	if (verbose > 3)
		fprintf(stderr, "[%s:%d] Freeing internal structure.\n",
				__func__, __LINE__);
	if (ei.fd >= 0)
		close(ei.fd);
	ei.fd = -1;
	ei.strsectbl_size = 0;
	if (ei.strsectbl) {
		free(ei.strsectbl);
		ei.strsectbl = NULL;
	}
	if (ei.sechdrs) {
		free(ei.sechdrs);
		ei.sechdrs = NULL;
	}
	if (ei.proghdrs) {
		free(ei.proghdrs);
		ei.proghdrs = NULL;
	}
	if (rc < 0) {
		if (ei.interp.name)
			free(ei.interp.name);
		ei.interp.name = NULL;
		if (ei.symbols) {
			size_t idx;
			for (idx = 0; idx < ei.symbols_num; ++idx) {
				free(ei.symbols[idx].name);
				ei.symbols[idx].name = NULL;
			}
			free(ei.symbols);
		}
		ei.symbols = NULL;
		ei.symbols_num = 0;
	} else {
		if (verbose > 2)
			fprintf(stderr, "[%s:%d] Readying return values.\n",
				__func__, __LINE__);
		symbols = ei.symbols;
		if (symbols_num)
			*symbols_num = ei.symbols_num;
		if (interp) {
			interp->name = ei.interp.name;
			interp->length = ei.interp.length;
			interp->ph_addr = ei.interp.ph_addr;
		} else {
			if (ei.interp.name)
				free(ei.interp.name);
			ei.interp.name = NULL;
		}
		if (is64)
			*is64 = ei.is64;
		if (entry_point)
			*entry_point = ei.entry_point;
	}
	return symbols;
}

int elf_symbol_cmpqsort(const void *p1, const void *p2)
{
	return strcmp(((const struct elf_symbol *)p1)->name,
				  ((const struct elf_symbol *)p2)->name);
}
