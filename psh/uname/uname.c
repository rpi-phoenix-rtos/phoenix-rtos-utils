/*
 * Phoenix-RTOS
 *
 * uname - print system information
 *
 * Copyright 2026 Phoenix Systems
 * Author: Claude (Phoenix-RTOS RPi4 port)
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "../psh.h"


/* Field selection flags (POSIX uname). */
#define UN_SYSNAME  (1 << 0)
#define UN_NODENAME (1 << 1)
#define UN_RELEASE  (1 << 2)
#define UN_VERSION  (1 << 3)
#define UN_MACHINE  (1 << 4)
#define UN_ALL      (UN_SYSNAME | UN_NODENAME | UN_RELEASE | UN_VERSION | UN_MACHINE)


static void psh_uname_info(void)
{
	printf("print system information");
}


static void psh_uname_help(const char *prog)
{
	printf("Usage: %s [-asnrvm]\n"
		"  -a   print all information\n"
		"  -s   kernel name (default)\n"
		"  -n   network node hostname\n"
		"  -r   kernel release\n"
		"  -v   kernel version\n"
		"  -m   machine hardware name\n",
		prog);
}


/* Append a field to the output line, space-separated. */
static void psh_uname_put(const char *field, int *first)
{
	if (*first == 0) {
		putchar(' ');
	}
	fputs(field, stdout);
	*first = 0;
}


int psh_uname(int argc, char **argv)
{
	struct utsname u;
	unsigned int flags = 0;
	int c, first = 1;

	optind = 1;
	while ((c = getopt(argc, argv, "asnrvmh")) != -1) {
		switch (c) {
			case 'a': flags |= UN_ALL; break;
			case 's': flags |= UN_SYSNAME; break;
			case 'n': flags |= UN_NODENAME; break;
			case 'r': flags |= UN_RELEASE; break;
			case 'v': flags |= UN_VERSION; break;
			case 'm': flags |= UN_MACHINE; break;
			case 'h': psh_uname_help(argv[0]); return EXIT_SUCCESS;
			default: psh_uname_help(argv[0]); return EXIT_FAILURE;
		}
	}

	/* POSIX: with no options behave as -s. */
	if (flags == 0) {
		flags = UN_SYSNAME;
	}

	if (uname(&u) != 0) {
		fprintf(stderr, "uname: cannot get system information\n");
		return EXIT_FAILURE;
	}

	if ((flags & UN_SYSNAME) != 0) {
		psh_uname_put(u.sysname, &first);
	}
	if ((flags & UN_NODENAME) != 0) {
		psh_uname_put(u.nodename, &first);
	}
	if ((flags & UN_RELEASE) != 0) {
		psh_uname_put(u.release, &first);
	}
	if ((flags & UN_VERSION) != 0) {
		psh_uname_put(u.version, &first);
	}
	if ((flags & UN_MACHINE) != 0) {
		psh_uname_put(u.machine, &first);
	}
	putchar('\n');

	return EXIT_SUCCESS;
}


void __attribute__((constructor)) uname_registerapp(void)
{
	static psh_appentry_t app = { .name = "uname", .run = psh_uname, .info = psh_uname_info };
	psh_registerapp(&app);
}
