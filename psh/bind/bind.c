/*
 * Phoenix-RTOS
 *
 * bind - binds device to directory
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
#include <unistd.h>

#include <sys/file.h>
#include <sys/msg.h>
#include <sys/stat.h>

#include "../psh.h"


/* The kernel spawns syspage programs concurrently, so a boot-time bind
 * (e.g. `bind devfs /dev`) can run before its source (devfs) or target
 * (/dev) is registered. Retry the lookups like create_dev does instead of
 * failing the bind and leaving the target directory unforwarded. */
#define BIND_LOOKUP_RETRIES  30
#define BIND_LOOKUP_DELAY_US 100000


static int psh_bindLookup(const char *name, oid_t *oid)
{
	int retry, err;

	for (retry = 0; ((err = lookup(name, NULL, oid)) < 0) && (retry < BIND_LOOKUP_RETRIES); retry++) {
		usleep(BIND_LOOKUP_DELAY_US);
	}

	return err;
}


void psh_bindinfo(void)
{
	printf("binds device to directory");
}


int psh_bind(int argc, char **argv)
{
	msg_t msg = { 0 };
	oid_t soid, doid;
	struct stat buf;
	int err;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <source> <target>\n", argv[0]);
		return -EINVAL;
	}

	if (psh_bindLookup(argv[1], &soid) < 0)
		return -ENOENT;

	if (psh_bindLookup(argv[2], &doid) < 0)
		return -ENOENT;

	if ((err = stat(argv[2], &buf)))
		return err;

	if (!S_ISDIR(buf.st_mode))
		return -ENOTDIR;

	msg.type = mtSetAttr;
	msg.oid = doid;
	msg.i.attr.type = atDev;
	msg.i.data = &soid;
	msg.i.size = sizeof(oid_t);

	err = msgSend(doid.port, &msg);

	return (err < 0) ? err : msg.o.err;
}


void __attribute__((constructor)) bind_registerapp(void)
{
	static psh_appentry_t app = {.name = "bind", .run = psh_bind, .info = psh_bindinfo};
	psh_registerapp(&app);
}
