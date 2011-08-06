/*
 *  hotpatch is a dll injection strategy.
 *  Copyright (C) 2010 Vikas Naresh Kumar
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
#ifdef HOTPATCH_HAS_ASSERT_H
	#undef NDEBUG
	#include <assert.h>
#endif

int main(int argc, char **argv, char **envp)
{
	int st = 0;
	int memfd = -1;
	pid_t pid = getpid();
	char procfile[4096];
	memset(procfile, 0, sizeof(procfile));
	sprintf(procfile, "/proc/%d/maps", pid);
	printf("Trying to open %s\n", procfile);
	memfd = open(procfile, O_RDONLY);
	assert(memfd >= 0);
	memset(procfile, 0, sizeof(procfile));
	while ((st = read(memfd, procfile, sizeof(procfile))) >= 0) {
		printf("st: %d\n", st);
		printf("%s\n", procfile);
		if (st == 0) break;
	}
	if (st < 0) {
		st = errno;
		printf("error: %s\n", strerror(st));
	}
	return st;
}
