/*
 * Phoenix-RTOS
 *
 * logread - view the captured system log (/var/log/messages) — task #31
 *
 * Companion to `dmesg`: where dmesg streams the live kernel ring buffer,
 * logread cats (or follows, with -f) the persistent /var/log/messages file
 * written by the rpi4-klogd daemon in the USER logging build mode. This is the
 * Linux-like "view the log file" command.
 *
 * Copyright 2026 Phoenix Systems
 * Author: Witold Bołt
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../psh.h"


#define LOG_FILE "/var/log/messages"

/* Poll interval when following (-f) and the file has no new data. */
#define LOGREAD_FOLLOW_DELAY_US 200000 /* 200 ms */


void psh_logreadinfo(void)
{
	printf("view the system log file (" LOG_FILE ")");
}


static void psh_logread_help(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("  -f:  follow — keep printing as the log grows (Ctrl-C to stop)\n");
	printf("  -h:  shows this help message\n");
}


int psh_logread(int argc, char **argv)
{
	bool follow = false;
	int fd;

	for (;;) {
		int c = getopt(argc, argv, "fh");
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'f':
				follow = true;
				break;

			case 'h':
				psh_logread_help(argv[0]);
				return EXIT_SUCCESS;

			default:
				psh_logread_help(argv[0]);
				return EXIT_FAILURE;
		}
	}

	fd = open(LOG_FILE, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "logread: cannot open %s: %s\n", LOG_FILE, strerror(errno));
		fprintf(stderr, "logread: is the USER logging mode (RPI4_LOG_TO_FILE) enabled?\n");
		return EXIT_FAILURE;
	}

	for (;;) {
		char buf[256];
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "logread: read %s failed: %s\n", LOG_FILE, strerror(errno));
			close(fd);
			return EXIT_FAILURE;
		}

		if (n == 0) {
			/* End of file: stop unless following, then wait for more data. */
			if (!follow) {
				break;
			}
			if (psh_common.sigint != 0) {
				break;
			}
			usleep(LOGREAD_FOLLOW_DELAY_US);
			continue;
		}

		if (psh_write(STDOUT_FILENO, buf, (size_t)n) != (size_t)n) {
			close(fd);
			return EXIT_FAILURE;
		}
	}

	close(fd);

	return EXIT_SUCCESS;
}


void __attribute__((constructor)) logread_registerapp(void)
{
	static psh_appentry_t app = { .name = "logread", .run = psh_logread, .info = psh_logreadinfo };
	psh_registerapp(&app);
}
