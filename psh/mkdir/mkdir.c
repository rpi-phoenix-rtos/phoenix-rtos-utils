/*
 * Phoenix-RTOS
 *
 *  mkdir - creates directory
 *
 * Copyright 2017, 2018, 2020, 2021 Phoenix Systems
 * Author: Pawel Pisarczyk, Jan Sikorski, Maciej Purski, Lukasz Kosinski, Mateusz Niewiadomski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "../psh.h"


void psh_mkdirinfo(void)
{
	printf("creates directory");
}


/* A path that already names a directory is not an error for -p. */
static int psh_mkdir_isdir(const char *path)
{
	struct stat st;

	return ((stat(path, &st) == 0) && S_ISDIR(st.st_mode)) ? 1 : 0;
}


/* mkdir -p: create each missing component of path in turn, leaving the ones
 * that already exist as directories alone (POSIX mkdir -p). */
static int psh_mkdir_parents(char *path)
{
	char *p = path;
	char c;

	for (;;) {
		/* Skip this component's leading slashes, then move to its end. */
		while (*p == '/') {
			p++;
		}
		while ((*p != '\0') && (*p != '/')) {
			p++;
		}

		c = *p;
		*p = '\0';
		if (mkdir(path, 0) < 0) {
			int e = errno;

			if ((e != EEXIST) || (psh_mkdir_isdir(path) == 0)) {
				*p = c;
				errno = e;
				return -1;
			}
		}
		*p = c;

		while (*p == '/') {
			p++;
		}
		if (*p == '\0') {
			return 0;
		}
	}
}


static void psh_mkdir_usage(const char *progname)
{
	fprintf(stderr, "usage: %s [-p] <dir path>...\n", progname);
	fprintf(stderr, "  -p  create missing parent directories; an existing directory is not an error\n");
}


int psh_mkdir(int argc, char **argv)
{
	int i, c, err, parents = 0;

	while ((c = getopt(argc, argv, "ph")) != -1) {
		switch (c) {
			case 'p':
				parents = 1;
				break;
			case 'h':
				psh_mkdir_usage(argv[0]);
				return EXIT_SUCCESS;
			default:
				psh_mkdir_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		psh_mkdir_usage(argv[0]);
		return EXIT_FAILURE;
	}

	err = EXIT_SUCCESS;
	for (i = optind; i < argc; i++) {
		if (((parents != 0) ? psh_mkdir_parents(argv[i]) : mkdir(argv[i], 0)) < 0) {
			err = EXIT_FAILURE;
			fprintf(stderr, "mkdir: failed to create %s directory: %s\n", argv[i], strerror(errno));
		}
	}

	return err;
}


void __attribute__((constructor)) mkdir_registerapp(void)
{
	static psh_appentry_t app = {.name = "mkdir", .run = psh_mkdir, .info = psh_mkdirinfo};
	psh_registerapp(&app);
}
