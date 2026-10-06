/*
 * Phoenix-RTOS
 *
 * prof - system-wide profiler: recording
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/perf.h>
#include <sys/stat.h>
#include <sys/threads.h>

#include "prof.h"


/*
 * One perf_read(). The kernel copies into it holding the trace spinlock with interrupts off, while
 * every CPU's events wait for that lock: keep it small, and touched beforehand so that the copy
 * takes no page fault.
 */
#define RECORD_BUFSZ    (64U << 10)
#define RECORD_DRAIN_MS 100U         /* kernel buffers are 4 MB per CPU: drained well before they fill */
#define RECORD_THREADS  1024
#define RECORD_LIBDIRS  "/bin:/sbin:/usr/bin:/usr/sbin:/lib:/usr/lib:/usr/local/bin:/usr/local/lib:/usr/libexec"


static volatile sig_atomic_t record_stop;


static void record_onSignal(int sig)
{
	(void)sig;
	record_stop = 1;
}


static uint64_t record_nowMs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}


/* Appends what the kernel holds of every channel to its file */
static int record_drain(int nchans, char *buf, FILE **files, size_t *total)
{
	int i, n;

	for (i = 0; i < nchans; i++) {
		do {
			n = perf_read(perf_mode_trace, buf, RECORD_BUFSZ, i);
			if (n < 0) {
				fprintf(stderr, "prof: perf_read(%d): %s\n", i, strerror(-n));
				return n;
			}
			if ((n > 0) && (fwrite(buf, 1, (size_t)n, files[i]) != (size_t)n)) {
				fprintf(stderr, "prof: write failed: %s\n", strerror(errno));
				return -EIO;
			}
			*total += (size_t)n;
		} while (n == (int)RECORD_BUFSZ);
	}

	return 0;
}


/* Files mapped by the recorded processes: where shared objects were loaded */
typedef struct {
	oid_t *oids;
	size_t n, cap;
} record_oids_t;


static void record_oidAdd(record_oids_t *o, const oid_t *oid)
{
	oid_t *n;
	size_t i;

	for (i = 0; i < o->n; i++) {
		if ((o->oids[i].port == oid->port) && (o->oids[i].id == oid->id)) {
			return;
		}
	}
	if (o->n == o->cap) {
		o->cap = (o->cap == 0U) ? 64U : o->cap * 2U;
		n = realloc(o->oids, o->cap * sizeof(*n));
		if (n == NULL) {
			return;
		}
		o->oids = n;
	}
	o->oids[o->n++] = *oid;
}


/* "map <pid> <vaddr> <size> <offs> <prot> <port> <id>" for every file mapping of pid */
static void record_maps(FILE *f, int pid, record_oids_t *oids)
{
	meminfo_t info;
	entryinfo_t *map = NULL, *n;
	int i, mapsz = 16;

	do {
		n = realloc(map, (size_t)mapsz * sizeof(*map));
		if (n == NULL) {
			free(map);
			return;
		}
		map = n;

		memset(&info, 0, sizeof(info));
		info.page.mapsz = -1;
		info.maps.mapsz = -1;
		info.entry.kmapsz = -1;
		info.entry.pid = (unsigned int)pid;
		info.entry.mapsz = mapsz;
		info.entry.map = map;
		meminfo(&info);
		if (info.entry.mapsz <= mapsz) {
			break;
		}
		mapsz = info.entry.mapsz;
	} while (1);

	for (i = 0; i < info.entry.mapsz; i++) {
		if (map[i].object == OBJECT_OID) {
			fprintf(f, "map %d 0x%llx 0x%zx 0x%llx %u %u %llu\n", pid, (unsigned long long)(uintptr_t)map[i].vaddr,
				map[i].size, map[i].offs, map[i].prot, (unsigned int)map[i].oid.port, (unsigned long long)map[i].oid.id);
			record_oidAdd(oids, &map[i].oid);
		}
	}

	free(map);
}


/* Process list and file mappings: the trace names threads too, this also gives parents and maps */
static void record_processes(FILE *f, const char *tag, record_oids_t *oids)
{
	threadinfo_t *info = malloc(sizeof(*info) * RECORD_THREADS);
	int i, j, n;

	if (info == NULL) {
		return;
	}

	n = threadsinfo(RECORD_THREADS, PH_THREADINFO_TID | PH_THREADINFO_PPID | PH_THREADINFO_NAME | PH_THREADINFO_STATE, info);
	for (i = 0; i < n; i++) {
		fprintf(f, "%s %u %d %d %.128s\n", tag, info[i].tid, (int)info[i].pid, (int)info[i].ppid, info[i].name);
	}
	for (i = 0; i < n; i++) {
		for (j = 0; (j < i) && (info[j].pid != info[i].pid); j++) {
		}
		if ((j == i) && (info[i].pid > 0)) {
			record_maps(f, (int)info[i].pid, oids);
		}
	}

	free(info);
}


/* "file <port> <id> <path>" for every mapped file found in dirs (':'-separated, not recursive) */
static void record_files(FILE *f, const char *dirs, const record_oids_t *oids)
{
	char path[PATH_MAX], *list = strdup(dirs), *dir, *save = NULL;
	struct dirent *d;
	struct stat st;
	size_t i, found = 0;
	DIR *dp;

	if (list == NULL) {
		return;
	}

	for (dir = strtok_r(list, ":", &save); (dir != NULL) && (found < oids->n); dir = strtok_r(NULL, ":", &save)) {
		dp = opendir(dir);
		if (dp == NULL) {
			continue;
		}
		while ((d = readdir(dp)) != NULL) {
			snprintf(path, sizeof(path), "%s/%s", dir, d->d_name);
			if ((stat(path, &st) < 0) || !S_ISREG(st.st_mode)) {
				continue;
			}
			for (i = 0; i < oids->n; i++) {
				if (((dev_t)oids->oids[i].port == st.st_dev) && ((ino_t)oids->oids[i].id == st.st_ino)) {
					fprintf(f, "file %u %llu %s\n", (unsigned int)oids->oids[i].port, (unsigned long long)oids->oids[i].id, path);
					found++;
					break;
				}
			}
		}
		closedir(dp);
	}

	free(list);
}


static void record_info(FILE *f, int pid, const perf_trace_cfg_t *cfg, unsigned int secs, int ncpus)
{
	fprintf(f, "version 1\npid %d\ncpus %d\nseconds %u\nperiod_us %u\ndepth %u\nsample_stack %u\nwait_stack %u\n",
		pid, ncpus, secs, cfg->samplePeriodUs, cfg->depth, cfg->sampleStack, cfg->waitStack);
}


static int record_open(const char *dir, int nchans, FILE **files)
{
	char path[PATH_MAX];
	int i;

	for (i = 0; i < nchans; i++) {
		snprintf(path, sizeof(path), "%s/%s%d", dir,
			((i % (int)trace_channel_count) == (int)trace_channel_meta) ? "channel_meta" : "channel_event",
			i / (int)trace_channel_count);
		files[i] = fopen(path, "wb");
		if (files[i] == NULL) {
			fprintf(stderr, "prof: %s: %s\n", path, strerror(errno));
			return -1;
		}
	}

	return 0;
}


int prof_record(int argc, char **argv)
{
	perf_trace_cfg_t cfg = { .samplePeriodUs = 1000, .depth = 16, .sampleStack = 512, .waitStack = 512 };
	const char *dir = PROF_DEFAULT_DIR, *libdirs = RECORD_LIBDIRS;
	record_oids_t oids = { 0 };
	unsigned int secs = 10, flags = PERF_TRACE_FLAG_SAMPLE;
	int opt, pid = 0, nchans, i, err = 0;
	FILE **files = NULL, *finfo;
	char path[PATH_MAX], *buf;
	uint64_t start, deadline;
	size_t total = 0;
	struct stat st;

	optind = 1;
	while ((opt = getopt(argc, argv, "t:o:p:f:d:s:w:rL:")) != -1) {
		switch (opt) {
			case 't':
				secs = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'o':
				dir = optarg;
				break;
			case 'p':
				pid = (int)strtol(optarg, NULL, 0);
				break;
			case 'f':
				cfg.samplePeriodUs = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'd':
				cfg.depth = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 's':
				cfg.sampleStack = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.waitStack = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'r':
				flags |= PERF_TRACE_FLAG_ROLLING;
				break;
			case 'L':
				libdirs = optarg;
				break;
			default:
				fprintf(stderr, "prof: bad option, see `prof`\n");
				return 1;
		}
	}

	if ((secs == 0U) || (cfg.depth > PERF_TRACE_DEPTH_MAX) || (cfg.sampleStack > PERF_TRACE_USTACK_MAX) || (cfg.waitStack > PERF_TRACE_USTACK_MAX)) {
		fprintf(stderr, "prof: bad argument (depth <= %u, stack bytes <= %u)\n", PERF_TRACE_DEPTH_MAX, PERF_TRACE_USTACK_MAX);
		return 1;
	}

	if ((stat(dir, &st) < 0) && (mkdir(dir, 0777) < 0)) {
		fprintf(stderr, "prof: mkdir %s: %s\n", dir, strerror(errno));
		return 1;
	}

	buf = malloc(RECORD_BUFSZ);
	if (buf == NULL) {
		fprintf(stderr, "prof: out of memory\n");
		return 1;
	}
	memset(buf, 0, RECORD_BUFSZ);

	signal(SIGINT, record_onSignal);
	signal(SIGTERM, record_onSignal);

	snprintf(path, sizeof(path), "%s/%s", dir, PROF_INFO_FILE);
	finfo = fopen(path, "w");
	if (finfo == NULL) {
		fprintf(stderr, "prof: %s: %s\n", path, strerror(errno));
		free(buf);
		return 1;
	}
	record_processes(finfo, "thread", &oids);

	nchans = perf_start(perf_mode_trace, flags, &cfg, sizeof(cfg));
	if (nchans < 0) {
		fprintf(stderr, "prof: perf_start: %s%s\n", strerror(-nchans),
			(nchans == -ENOSYS) ? " (no thread sampling on this kernel/architecture)" : "");
		fclose(finfo);
		free(buf);
		return 1;
	}
	record_info(finfo, pid, &cfg, secs, nchans / (int)trace_channel_count);

	files = calloc((size_t)nchans, sizeof(*files));
	if ((files == NULL) || (record_open(dir, nchans, files) < 0)) {
		err = -1;
	}

	fprintf(stderr, "prof: recording %u s on %d CPUs into %s (Ctrl-C ends early)\n", secs, nchans / (int)trace_channel_count, dir);

	start = record_nowMs();
	deadline = start + (uint64_t)secs * 1000U;
	while ((err == 0) && (record_stop == 0) && (record_nowMs() < deadline)) {
		if ((flags & PERF_TRACE_FLAG_ROLLING) == 0U) {
			err = record_drain(nchans, buf, files, &total);
		}
		usleep(RECORD_DRAIN_MS * 1000U);
	}

	if (perf_stop(perf_mode_trace) >= 0) {
		if (err == 0) {
			err = record_drain(nchans, buf, files, &total);
		}
	}
	(void)perf_finish(perf_mode_trace);

	/* After the trace: the processes started during it, and the paths of what they all mapped */
	record_processes(finfo, "thread-end", &oids);
	record_files(finfo, libdirs, &oids);
	fclose(finfo);
	free(oids.oids);

	if (files != NULL) {
		for (i = 0; i < nchans; i++) {
			if (files[i] != NULL) {
				fclose(files[i]);
			}
		}
		free(files);
	}
	free(buf);

	fprintf(stderr, "prof: %.1f s, %zu bytes in %s%s\n", (double)(record_nowMs() - start) / 1000.0, total, dir,
		(err == 0) ? "" : " (incomplete: error above)");
	if (err == 0) {
		fprintf(stderr, "prof: `prof report %s` here, or scripts/prof-report.py on the host for symbols\n", dir);
	}

	return (err == 0) ? 0 : 1;
}
