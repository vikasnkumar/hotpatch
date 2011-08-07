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

struct hp_options {
    pid_t pid;
    int verbose;
};

void print_usage(const char *app)
{
    printf("\nUsage: %s [options] <PID of process to patch>\n", app);
	printf("\nOptions:\n");
	printf("-h           This help message.\n");
	printf("-v[vvvv]     Enable verbose logging. Add more 'v's for more\n");
}

void print_options(const struct hp_options *opts)
{
	if (opts && opts->verbose > 0) {
		printf(
				"Options Given:\n"
				"Verbose Level: %d\n"
				"Process PID: %d\n",
				opts->verbose,
				opts->pid
			  );
	}
}

int parse_arguments(int argc, char **argv, struct hp_options *opts)
{
    if (argc > 0 && argv && opts) {
        int opt = 0;
        extern int optind;
        extern char *optarg;
        optind = 1;
        while ((opt = getopt(argc, argv, "hv::")) != -1) {
            switch (opt) {
            case 'v':
                opts->verbose += optarg ? (int)strnlen(optarg, 5) : 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return -1;
            }
        }
        if (optind >= argc) {
            printf("Expected more arguments.\n");
            print_usage(argv[0]);
            return -1;
        }
        opts->pid = (pid_t)strtol(argv[optind], NULL, 10);
        if (opts->pid == 0) {
            printf("Process PID can't be 0. Tried parsing: %s\n", argv[optind]);
			return -1;
        }
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    struct hp_options opts = { 0 };
    hotpatch_t *hp = NULL;
    /* parse all arguments first */
    if (parse_arguments(argc, argv, &opts) < 0) {
        return -1;
    }
    print_options(&opts);
	hp = hotpatch_create(opts.pid, opts.verbose);
	if (!hp) {
		fprintf(stderr, "[%s:%d] Unable to create hotpatch for PID %d\n",
				__func__, __LINE__, opts.pid);
		return -1;
	}
	hotpatch_destroy(hp);
	hp = NULL;
    return 0;
}
