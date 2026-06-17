/*
 * Phoenix-RTOS
 *
 * mv - move (rename) files
 *
 * Copyright 2026 Phoenix Systems
 * Author: Witold Bołt
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>

#include "../psh.h"

#define SIZE_BUFF 256


static void psh_mvinfo(void)
{
	printf("move (rename) file");
}


static void psh_mv_help(const char *prog)
{
	printf("Usage: %s SOURCE TARGET\n", prog);
	printf("  move/rename SOURCE to TARGET (TARGET may be a directory)\n");
	printf("  -h:  shows this help message\n");
}


/* Cross-device fallback: copy SOURCE to dest then remove SOURCE. */
static int psh_mv_copy(const char *srcpath, const char *dstpath)
{
	int fdsrc, fddst;
	unsigned char buff[SIZE_BUFF];
	struct stat st;
	ssize_t cnt, wcnt, off;
	int retval = EXIT_SUCCESS;

	fdsrc = open(srcpath, O_RDONLY);
	if (fdsrc < 0) {
		perror("mv: could not open source file");
		return EXIT_FAILURE;
	}

	if ((fstat(fdsrc, &st) < 0) || !S_ISREG(st.st_mode)) {
		close(fdsrc);
		fprintf(stderr, "mv: source is not a regular file\n");
		return EXIT_FAILURE;
	}

	fddst = open(dstpath, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
	if (fddst < 0) {
		close(fdsrc);
		perror("mv: could not open destination file");
		return EXIT_FAILURE;
	}

	for (;;) {
		cnt = read(fdsrc, buff, sizeof(buff));
		if (cnt < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("mv: read failure");
			retval = EXIT_FAILURE;
			break;
		}
		if (cnt == 0) {
			break;
		}
		for (off = 0; off < cnt; off += wcnt) {
			wcnt = write(fddst, buff + off, (size_t)(cnt - off));
			if (wcnt < 0) {
				if (errno == EINTR) {
					wcnt = 0;
					continue;
				}
				perror("mv: write failure");
				retval = EXIT_FAILURE;
				break;
			}
		}
		if (retval != EXIT_SUCCESS) {
			break;
		}
	}

	close(fdsrc);
	close(fddst);

	if (retval == EXIT_SUCCESS) {
		if (unlink(srcpath) < 0) {
			perror("mv: could not remove source after copy");
			retval = EXIT_FAILURE;
		}
	}

	return retval;
}


static int psh_mv(int argc, char **argv)
{
	char *src, *target, *destpath = NULL, *filename;
	const char *dest;
	struct stat st;
	size_t destlen, filelen;
	int c, retval = EXIT_SUCCESS;

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch (c) {
			case 'h':
				psh_mv_help(argv[0]);
				return EXIT_SUCCESS;
			default:
				psh_mv_help(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (argc - optind != 2) {
		psh_mv_help(argv[0]);
		return EXIT_FAILURE;
	}

	src = argv[optind];
	target = argv[optind + 1];
	dest = target;

	/* If TARGET is a directory, move SOURCE into it under its basename. */
	if ((stat(target, &st) == 0) && S_ISDIR(st.st_mode)) {
		filename = basename(src);
		destlen = strlen(target);
		filelen = strlen(filename);
		destpath = malloc(destlen + filelen + 2);
		if (destpath == NULL) {
			perror("mv");
			return EXIT_FAILURE;
		}
		strcpy(destpath, target);
		destpath[destlen] = '/';
		strcpy(destpath + destlen + 1, filename);
		dest = destpath;
	}

	if (rename(src, dest) != 0) {
		if (errno == EXDEV) {
			/* Cross-device: fall back to copy + remove. */
			retval = psh_mv_copy(src, dest);
		}
		else {
			perror("mv");
			retval = EXIT_FAILURE;
		}
	}

	free(destpath);

	return retval;
}


void __attribute__((constructor)) mv_registerapp(void)
{
	static psh_appentry_t app = { .name = "mv", .run = psh_mv, .info = psh_mvinfo };
	psh_registerapp(&app);
}
