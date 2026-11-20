/*
 * Phoenix-RTOS
 *
 * df - print filesystem statistics
 *
 * Copyright 2022 Phoenix Systems
 * Author: Lukasz Kosinski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/statvfs.h>

#include "../psh.h"


typedef struct {
	char *fsname;
	char *type;
	char *dir;
} psh_df_mnt_t;


static void psh_df_info(void)
{
	printf("print filesystem statistics");
}


static void psh_df_help(const char *prog)
{
	printf("Usage: %s [options] [files]\n", prog);
	printf("  -T:  print filesystem type\n");
	printf("  -i:  print inode information instead of block usage\n");
	printf("  -h:  print this help message\n");
}


static void psh_df_mntFree(psh_df_mnt_t *mnt)
{
	free(mnt->fsname);
	free(mnt->type);
	free(mnt->dir);
	mnt->fsname = mnt->type = mnt->dir = NULL;
}


static int psh_df_mntSet(psh_df_mnt_t *mnt, const struct mntent *ent)
{
	psh_df_mntFree(mnt);
	mnt->fsname = strdup(ent->mnt_fsname);
	mnt->type = strdup(ent->mnt_type);
	mnt->dir = strdup(ent->mnt_dir);

	if ((mnt->fsname == NULL) || (mnt->type == NULL) || (mnt->dir == NULL)) {
		psh_df_mntFree(mnt);
		return -ENOMEM;
	}

	return 0;
}


/* Is path on dir or below it? */
static int psh_df_isBelow(const char *path, const char *dir)
{
	size_t len = strlen(dir);

	if ((dir[0] == '/') && (dir[1] == '\0')) {
		return 1;
	}

	return ((strncmp(path, dir, len) == 0) && ((path[len] == '\0') || (path[len] == '/'))) ? 1 : 0;
}


/* Finds the mount holding path: the longest mount point it is on or below. */
static int psh_df_findMnt(const char *path, psh_df_mnt_t *mnt)
{
	struct mntent *ent;
	size_t best = 0;
	int found = 0;
	FILE *table = setmntent(MOUNTED, "r");

	if (table == NULL) {
		return -1;
	}

	while ((ent = getmntent(table)) != NULL) {
		size_t len = strlen(ent->mnt_dir);
		if ((psh_df_isBelow(path, ent->mnt_dir) != 0) && ((found == 0) || (len > best))) {
			if (psh_df_mntSet(mnt, ent) == 0) {
				best = len;
				found = 1;
			}
		}
	}
	(void)endmntent(table);

	return (found != 0) ? 0 : -1;
}


static int psh_df_print(const char *fsname, const char *fstype, const char *dir, int type, int inodes)
{
	struct statvfs st;
	fsblkcnt_t used;
	unsigned long long unit = 1024;

	if (statvfs(dir, &st) < 0) {
		fprintf(stderr, "df: %s: %s\n", dir, strerror(errno));
		return -1;
	}

	if (inodes) {
		st.f_blocks = st.f_files;
		st.f_bavail = st.f_bfree = st.f_ffree;
		st.f_frsize = 1;
		unit = 1;
	}
	used = st.f_blocks - st.f_bfree;

	printf("%-15s", fsname);
	if (type) {
		printf(" %-10s", fstype);
	}
	printf(" %9llu %9llu %9llu %7llu%% %s\n",
		((unsigned long long)st.f_blocks * st.f_frsize + unit / 2) / unit,
		((unsigned long long)used * st.f_frsize + unit / 2) / unit,
		((unsigned long long)st.f_bavail * st.f_frsize + unit / 2) / unit,
		(used + st.f_bavail) ? (100ULL * used + (used + st.f_bavail) / 2) / (used + st.f_bavail) : 0ULL,
		dir);

	return 0;
}


/* Prints every mounted filesystem. "/" is always printed, also when the mount
 * table is missing or its server does not record itself there. */
static int psh_df_all(int type, int inodes)
{
	struct mntent *ent;
	int ret = EXIT_SUCCESS;
	FILE *table = setmntent(MOUNTED, "r");

	/* The table is sorted by directory: "/", when listed, is first. */
	ent = (table != NULL) ? getmntent(table) : NULL;
	if (((ent == NULL) || (strcmp(ent->mnt_dir, "/") != 0)) && (psh_df_print("-", "-", "/", type, inodes) < 0)) {
		ret = EXIT_FAILURE;
	}

	for (; ent != NULL; ent = getmntent(table)) {
		if (psh_df_print(ent->mnt_fsname, ent->mnt_type, ent->mnt_dir, type, inodes) < 0) {
			ret = EXIT_FAILURE;
		}
	}

	if (table != NULL) {
		(void)endmntent(table);
	}

	return ret;
}


/* Prints the filesystem holding each of the given files. */
static int psh_df_files(char **files, int count, int type, int inodes)
{
	psh_df_mnt_t mnt = { NULL, NULL, NULL };
	int i, ret = EXIT_SUCCESS;
	char *path;

	for (i = 0; i < count; ++i) {
		path = realpath(files[i], NULL);
		if (path == NULL) {
			fprintf(stderr, "df: %s: %s\n", files[i], strerror(errno));
			ret = EXIT_FAILURE;
			continue;
		}

		if (psh_df_findMnt(path, &mnt) == 0) {
			if (psh_df_print(mnt.fsname, mnt.type, mnt.dir, type, inodes) < 0) {
				ret = EXIT_FAILURE;
			}
			psh_df_mntFree(&mnt);
		}
		else if (psh_df_print("-", "-", path, type, inodes) < 0) {
			ret = EXIT_FAILURE;
		}
		free(path);
	}

	return ret;
}


static int psh_df(int argc, char **argv)
{
	int c, type = 0, inodes = 0;

	while ((c = getopt(argc, argv, "Tih")) != -1) {
		switch (c) {
			case 'T':
				type = 1;
				break;

			case 'i':
				inodes = 1;
				break;

			case 'h':
				psh_df_help(argv[0]);
				return EXIT_SUCCESS;

			default:
				psh_df_help(argv[0]);
				return EXIT_FAILURE;
		}
	}

	printf("Filesystem     %s %-9s      Used Available Capacity Mounted on\n",
		(type) ? " Type      " : "",
		(inodes) ? "   Inodes" : "1K-blocks");

	if (optind == argc) {
		return psh_df_all(type, inodes);
	}

	return psh_df_files(argv + optind, argc - optind, type, inodes);
}


void __attribute__((constructor)) df_registerapp(void)
{
	static psh_appentry_t app = { .name = "df", .run = psh_df, .info = psh_df_info };
	psh_registerapp(&app);
}
