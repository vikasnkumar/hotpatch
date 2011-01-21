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

int os_get_exe_fd(pid_t pid)
{
	int fd = -1;
	if (pid > 0) {
		char buf[OS_MAX_BUFFER];
		memset(&buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
		fd = open(buf, O_RDONLY);
		if (fd < 0) {
			int st = errno;
			fprintf(stderr, "[%s:%d] File opening error. Error: %s\n",
					__func__, __LINE__, strerror(st));
		}
	}
	return fd;
}

struct dyldo {
	int inserted;
	char *exename;
	int fd_exe;
};

void *dyldo_takeout()
{
	struct dyldo *dy = NULL;
	dy = malloc(sizeof(*dy));
	if (dy) {
		dy->inserted = 0;
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

int dyldo_insert(void *dy, pid_t pid, const char *dll, const char *symbol,
				void *arg)
{
	if (!dy || pid <= 0) {
		return -1;
	}
	dy->fd_exe = os_get_exe_fd(pid);
	return 0;
}
