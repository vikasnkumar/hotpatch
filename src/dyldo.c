/*
 *  dyldo is a dll injection strategy.
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
#include <dyldo_config.h>
#include <dyldo.h>

#define OS_MAX_BUFFER 512
#define ERROR_OUT_OF_MEMORY do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] Out of memory. Error: %s\n", __func__, __LINE__, strerror(err)); \
} while (0)
#define ERROR_FILE_OPEN(FF) do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File(%s) open error. Error: %s\n", __func__, __LINE__, FF, strerror(err)); \
} while (0)
#define ERROR_FILE_SEEK do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File seek error. Error: %s\n", __func__, __LINE__, strerror(err)); \
} while (0)
#define ERROR_FILE_READ do { \
	int err = errno; \
	fprintf(stderr, "[%s:%d] File read error. Error: %s\n", __func__, __LINE__, strerror(err)); \
} while (0)
#define ERROR_UNSUPPORTED_PROCESSOR do { \
	fprintf(stderr, \
	"[%s:%d] Only 32/64-bit Intel X86/X86-64 processors are supported.\n", __func__, __LINE__); \
} while (0)

struct dyldo {
	int inserted;
	char *exename;
	int fd_exe;
};

int exe_open_file(pid_t pid)
{
	int fd = -1;
	if (pid > 0) {
		char buf[OS_MAX_BUFFER];
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			ERROR_FILE_OPEN(buf);
		}
	}
	return fd;
}

int exe_elf_identify(unsigned char *e_ident, size_t size)
{
	if (e_ident && size > 0) {
		if ((e_ident[EI_MAG0] == ELFMAG0) &&
			(e_ident[EI_MAG1] == ELFMAG1) &&
			(e_ident[EI_MAG2] == ELFMAG2) &&
			(e_ident[EI_MAG3] == ELFMAG3)) {
			int is64 = -1;
			/* magic number says this is an ELF file */
			switch (e_ident[EI_CLASS]) {
			case ELFCLASS32:
				is64 = 0;
				break;
			case ELFCLASS64:
				is64 = 1;
				break;
			case ELFCLASSNONE:
			default:
				is64 = -1;
				break;
			}
			if (is64 >= 0) {
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
	return -1;
}

int exe_headers32(int fd)
{
	Elf32_Ehdr hdr;
	Elf32_Shdr *sechdrs = NULL;
	memset(&hdr, 0, sizeof(hdr));
	if (lseek(fd, 0, SEEK_SET) < 0) {
		ERROR_FILE_SEEK;
		return -1;
	}
	if (read(fd, &hdr, sizeof(hdr)) < 0) {
		ERROR_FILE_READ;
		return -1;
	}
	if (exe_elf_identify(hdr.e_ident, EI_NIDENT) == 1) {
		/* this is a 64-bit file. so return */
		return 1;
	}
	if (hdr.e_machine != EM_386) {
		ERROR_UNSUPPORTED_PROCESSOR;
		return -1;
	}
	if (hdr.e_shnum > 0) {
		sechdrs = malloc(hdr.e_shentsize * hdr.e_shnum);
		if (!sechdrs) {
			ERROR_OUT_OF_MEMORY;
			return -1;
		}
		memset(sechdrs, 0, hdr.e_shentsize * hdr.e_shnum);
		do {
			if (lseek(fd, hdr.e_shoff, SEEK_SET) < 0) {
				ERROR_FILE_SEEK;
				break;
			}
			if (read(fd, sechdrs, hdr.e_shnum * hdr.e_shentsize) < 0) {
				ERROR_FILE_READ;
				break;
			}
		} while (0);
		free(sechdrs);
		sechdrs = NULL;
	}
	return 0;
}

int exe_headers64(int fd)
{
	Elf64_Ehdr hdr;
	Elf64_Shdr *sechdrs = NULL;
	memset(&hdr, 0, sizeof(hdr));
	if (lseek(fd, 0, SEEK_SET) < 0) {
		ERROR_FILE_SEEK;
		return -1;
	}
	if (read(fd, &hdr, sizeof(hdr)) < 0) {
		ERROR_FILE_READ;
		return -1;
	}
	if (hdr.e_machine != EM_X86_64) {
		ERROR_UNSUPPORTED_PROCESSOR;
		return -1;
	}
	if (hdr.e_shnum > 0) {
		sechdrs = malloc(hdr.e_shentsize * hdr.e_shnum);
		if (!sechdrs) {
			ERROR_OUT_OF_MEMORY;
			return -1;
		}
		memset(sechdrs, 0, hdr.e_shentsize * hdr.e_shnum);
		do {
			if (lseek(fd, hdr.e_shoff, SEEK_SET) < 0) {
				ERROR_FILE_SEEK;
				break;
			}
			if (read(fd, sechdrs, hdr.e_shnum * hdr.e_shentsize) < 0) {
				ERROR_FILE_READ;
				break;
			}
		} while (0);
		free(sechdrs);
		sechdrs = NULL;
	}
	return 0;
}

int exe_get_headers(int fd)
{
	int is64 = 0;
	if (fd < 0) {
		return -1;
	}
	is64 = exe_headers32(fd);
	if (is64 > 0) {
		return exe_headers64(fd);
	}
	return is64;
}

void *dyldo_takeout()
{
	struct dyldo *dy = NULL;
	dy = malloc(sizeof(*dy));
	if (dy) {
		dy->inserted = 0;
	} else {
		ERROR_OUT_OF_MEMORY;
	}
	return dy;
}

void dyldo_putback(void *dy)
{
	if (dy) {
		free(dy);
		dy = NULL;
	}
}

int dyldo_insert(void *dy_in, pid_t pid, const char *dll, const char *symbol,
				void *arg)
{
	struct dyldo *dy = dy_in;
	if (!dy || pid <= 0) {
		return -1;
	}
	dy->fd_exe = exe_open_file(pid);
	if (dy->fd_exe < 0) {
		return -1;
	}
	exe_get_headers(dy->fd_exe);
	return 0;
}
