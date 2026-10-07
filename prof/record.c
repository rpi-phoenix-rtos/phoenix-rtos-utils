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
#include <fcntl.h>
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
#define RECORD_BUFSZ       (64U << 10)
#define RECORD_DRAIN_MS    100U /* kernel buffers are 4 MB per CPU: drained well before they fill */
#define RECORD_PASS_READS  32U  /* reads of one channel per pass: a pass is bounded, the deadline holds */
#define RECORD_MEM_MB      256U /* default cap of the in-memory recording */
#define RECORD_WRITE_CHUNK (1U << 20) /* one write() of a channel file */
#define RECORD_CAP_EVENT   (4U << 20) /* first allocation of a channel: the kernel's buffer size */
#define RECORD_CAP_META    (256U << 10)
#define RECORD_THREADS     1024
#define RECORD_LIBDIRS     "/bin:/sbin:/usr/bin:/usr/sbin:/lib:/usr/lib:/usr/local/bin:/usr/local/lib:/usr/libexec"


/*
 * The recording is kept in memory until the trace is stopped and only then written out. Writing
 * while tracing makes the recorder trace itself: every write to an NFS root is messages to the
 * file server, the network stack and the Ethernet driver, whose events outgrow what was written
 * (build 38: 942 MB in a minute for a 5 s recording that never ended).
 */
typedef struct {
	uint8_t *data;
	size_t len, cap;
} record_chan_t;


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


static int record_append(record_chan_t *c, int meta, const char *buf, size_t n)
{
	uint8_t *data;
	size_t cap;

	if (c->len + n > c->cap) {
		/* sized for a whole kernel buffer up front: fewer copies of a growing recording */
		cap = (c->cap == 0U) ? ((meta != 0) ? RECORD_CAP_META : RECORD_CAP_EVENT) : c->cap;
		while (cap < c->len + n) {
			cap *= 2U;
		}
		data = realloc(c->data, cap);
		if (data == NULL) {
			return -ENOMEM;
		}
		c->data = data;
		c->cap = cap;
	}
	memcpy(c->data + c->len, buf, n);
	c->len += n;

	return 0;
}


/*
 * Moves what the kernel holds into memory. bounded: at most RECORD_PASS_READS reads per channel,
 * so that a pass ends even if events come in faster than they are read. Returns -ENOSPC once
 * *total reaches limit.
 */
static int record_drain(int nchans, char *buf, record_chan_t *chans, size_t *total, size_t limit, int bounded)
{
	unsigned int k;
	int i, n;

	for (i = 0; i < nchans; i++) {
		for (k = 0; (bounded == 0) || (k < RECORD_PASS_READS); k++) {
			if (*total + RECORD_BUFSZ > limit) {
				return -ENOSPC;
			}
			n = perf_read(perf_mode_trace, buf, RECORD_BUFSZ, i);
			if (n < 0) {
				fprintf(stderr, "prof: perf_read(%d): %s\n", i, strerror(-n));
				return n;
			}
			if ((n > 0) && (record_append(&chans[i], ((i % (int)trace_channel_count) == (int)trace_channel_meta) ? 1 : 0, buf, (size_t)n) < 0)) {
				return -ENOSPC;
			}
			*total += (size_t)n;
			if (n < (int)RECORD_BUFSZ) {
				break;
			}
		}
	}

	return 0;
}


/* One channel file, in RECORD_WRITE_CHUNK writes: a slow or failing file server sees small requests */
static int record_writeFile(const char *path, const uint8_t *data, size_t len)
{
	size_t done = 0, n;
	ssize_t ret;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		fprintf(stderr, "prof: %s: %s\n", path, strerror(errno));
		return -1;
	}

	while (done < len) {
		n = ((len - done) < RECORD_WRITE_CHUNK) ? (len - done) : RECORD_WRITE_CHUNK;
		ret = write(fd, data + done, n);
		if (ret <= 0) {
			if ((ret < 0) && (errno == EINTR)) {
				continue;
			}
			fprintf(stderr, "prof: %s: write failed after %zu of %zu bytes: %s\n", path, done, len,
				(ret < 0) ? strerror(errno) : "no progress");
			close(fd);
			return -1;
		}
		done += (size_t)ret;
	}

	if (close(fd) < 0) {
		fprintf(stderr, "prof: %s: close: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}


/* Every channel file; a failed one does not stop the others */
static int record_write(const char *dir, int nchans, const record_chan_t *chans)
{
	char path[PATH_MAX];
	int i, err = 0;

	for (i = 0; i < nchans; i++) {
		snprintf(path, sizeof(path), "%s/%s%d", dir,
			((i % (int)trace_channel_count) == (int)trace_channel_meta) ? "channel_meta" : "channel_event",
			i / (int)trace_channel_count);
		if (record_writeFile(path, chans[i].data, chans[i].len) < 0) {
			err = -1;
		}
	}

	return err;
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


/* -e: classes recorded on top of the profile's */
static int record_classes(const char *list, unsigned int *classes)
{
	static const struct {
		const char *name;
		unsigned int bits;
	} names[] = {
		{ "sched", PERF_TRACE_EV_SCHED },
		{ "syscall", PERF_TRACE_EV_SYSCALL },
		{ "lock", PERF_TRACE_EV_LOCK },
		{ "irq", PERF_TRACE_EV_IRQ },
		{ "all", PERF_TRACE_EV_SCHED | PERF_TRACE_EV_SYSCALL | PERF_TRACE_EV_LOCK | PERF_TRACE_EV_IRQ },
	};
	const char *p = list, *end;
	size_t i, len;

	while (*p != '\0') {
		end = strchr(p, ',');
		len = (end != NULL) ? (size_t)(end - p) : strlen(p);
		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			if ((strlen(names[i].name) == len) && (strncmp(names[i].name, p, len) == 0)) {
				*classes |= names[i].bits;
				break;
			}
		}
		if (i == sizeof(names) / sizeof(names[0])) {
			return -1;
		}
		p += len + ((end != NULL) ? 1U : 0U);
	}

	return 0;
}


static void record_info(FILE *f, int pid, const perf_trace_cfg_t *cfg, unsigned int secs, int ncpus)
{
	fprintf(f, "version 3\npid %d\ncpus %d\nseconds %u\nperiod_us %u\ndepth %u\nsample_stack %u\nwait_stack %u\nwait_min_us %u\nwait_stack_min_us %u\nevents 0x%x\n",
		pid, ncpus, secs, cfg->samplePeriodUs, cfg->depth, cfg->sampleStack, cfg->waitStack, cfg->waitMinUs, cfg->waitStackMinUs, cfg->events);
}


int prof_record(int argc, char **argv)
{
	perf_trace_cfg_t cfg = { .samplePeriodUs = 2000, .depth = 16, .sampleStack = 512, .waitStack = 512, .waitMinUs = 1000, .events = 0,
		.waitStackMinUs = 10000 };
	unsigned int extra = 0;
	prof_mix_t *mix;
	const char *dir = PROF_DEFAULT_DIR, *libdirs = RECORD_LIBDIRS;
	record_oids_t oids = { 0 };
	unsigned int secs = 10, flags = PERF_TRACE_FLAG_SAMPLE, memMb = RECORD_MEM_MB;
	int opt, pid = 0, nchans, i, err = 0, full = 0;
	record_chan_t *chans = NULL;
	char path[PATH_MAX], *buf;
	uint64_t start, deadline, now, stopped;
	size_t total = 0, limit;
	struct stat st;
	FILE *finfo;

	optind = 1;
	while ((opt = getopt(argc, argv, "t:o:p:f:d:s:w:b:B:M:e:rL:")) != -1) {
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
			case 'b':
				cfg.waitMinUs = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'B':
				cfg.waitStackMinUs = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			case 'e':
				if (record_classes(optarg, &extra) < 0) {
					fprintf(stderr, "prof: -e takes a list of sched,syscall,lock,irq,all\n");
					return 1;
				}
				break;
			case 'M':
				memMb = (unsigned int)strtoul(optarg, NULL, 0);
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

	if ((secs == 0U) || (memMb == 0U) || (cfg.depth > PERF_TRACE_DEPTH_MAX) || (cfg.sampleStack > PERF_TRACE_USTACK_MAX) ||
		(cfg.waitStack > ((cfg.waitMinUs != 0U) ? PERF_TRACE_WAITSTACK_DEFERRED_MAX : PERF_TRACE_USTACK_MAX))) {
		fprintf(stderr, "prof: bad argument (depth <= %u, -s <= %u, -w <= %u, or <= %u with -b > 0)\n",
			PERF_TRACE_DEPTH_MAX, PERF_TRACE_USTACK_MAX, PERF_TRACE_USTACK_MAX, PERF_TRACE_WAITSTACK_DEFERRED_MAX);
		return 1;
	}
	limit = (size_t)memMb << 20;

	/*
	 * A profile: samples, the waits that last and who ended them, messages, thread names. The
	 * events of every switch, syscall, lock and interrupt come at the rate of those operations: -e.
	 * Every wait recorded when it begins (-b 0) is ended by thread_waking, a scheduling event.
	 */
	cfg.events = PERF_TRACE_EV_PROFILE | extra | ((cfg.waitMinUs == 0U) ? PERF_TRACE_EV_SCHED : 0U);

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

	/* everything written out before the trace starts or after it stops (see record_chan_t) */
	snprintf(path, sizeof(path), "%s/%s", dir, PROF_INFO_FILE);
	finfo = fopen(path, "w");
	if (finfo == NULL) {
		fprintf(stderr, "prof: %s: %s\n", path, strerror(errno));
		free(buf);
		return 1;
	}
	record_processes(finfo, "thread", &oids);
	fflush(finfo);

	nchans = perf_start(perf_mode_trace, flags, &cfg, sizeof(cfg));
	if (nchans < 0) {
		fprintf(stderr, "prof: perf_start: %s%s\n", strerror(-nchans),
			(nchans == -ENOSYS) ? " (no thread sampling on this kernel/architecture)" : "");
		fclose(finfo);
		free(buf);
		return 1;
	}

	chans = calloc((size_t)nchans, sizeof(*chans));
	if (chans == NULL) {
		err = -ENOMEM;
	}

	fprintf(stderr, "prof: recording %u s on %d CPUs, in memory (at most %u MB), then into %s\n", secs,
		nchans / (int)trace_channel_count, memMb, dir);

	/* The deadline is checked between bounded passes: the trace stops on time whatever comes in */
	start = record_nowMs();
	deadline = start + (uint64_t)secs * 1000U;
	for (now = start; (err == 0) && (record_stop == 0) && (now < deadline); now = record_nowMs()) {
		if ((flags & PERF_TRACE_FLAG_ROLLING) == 0U) {
			err = record_drain(nchans, buf, chans, &total, limit, 1);
		}
		now = record_nowMs();
		if ((err == 0) && (now < deadline)) {
			usleep((unsigned int)(((deadline - now) < RECORD_DRAIN_MS) ? (deadline - now) : RECORD_DRAIN_MS) * 1000U);
		}
	}
	if (err == -ENOSPC) {
		full = 1;
		err = 0;
	}

	(void)perf_stop(perf_mode_trace);
	stopped = record_nowMs();

	/* the kernel's buffers no longer grow: this ends */
	if ((err == 0) && (chans != NULL)) {
		err = record_drain(nchans, buf, chans, &total, limit, 0);
		if (err == -ENOSPC) {
			full = 1;
			err = 0;
		}
	}
	(void)perf_finish(perf_mode_trace);

	if (full != 0) {
		fprintf(stderr, "prof: the recording reached %u MB and was cut short (-M raises it; -b/-s/-w/-f lower the volume)\n", memMb);
	}

	/* what was recorded, from memory: printed even if writing it out fails */
	mix = calloc(1, sizeof(*mix));
	if ((mix != NULL) && (chans != NULL)) {
		for (i = 0; i < nchans; i++) {
			prof_mixAdd(mix, chans[i].data, chans[i].len, i / (int)trace_channel_count);
		}
		prof_mixPrint(stdout, mix, nchans / (int)trace_channel_count, (double)(stopped - start) / 1000.0);
		fflush(stdout);
	}
	free(mix);

	fprintf(finfo, "self %d\n", getpid());
	record_info(finfo, pid, &cfg, secs, nchans / (int)trace_channel_count);
	fprintf(finfo, "recorded_ms %llu\n", (unsigned long long)(stopped - start));

	if ((chans != NULL) && (record_write(dir, nchans, chans) < 0)) {
		err = -EIO;
	}

	/* after the trace: the processes started during it, and the paths of what they all mapped */
	record_processes(finfo, "thread-end", &oids);
	record_files(finfo, libdirs, &oids);
	fclose(finfo);
	free(oids.oids);

	fprintf(stderr, "prof: %.1f s, %zu bytes", (double)(stopped - start) / 1000.0, total);
	for (i = 0; (chans != NULL) && (i < nchans); i++) {
		fprintf(stderr, "%s%s%d %zu", (i == 0) ? " (" : ", ", ((i % 2) == 0) ? "meta" : "event", i / 2, chans[i].len);
		free(chans[i].data);
	}
	fprintf(stderr, "%s in %s%s\n", (chans != NULL) ? ")" : "", dir, (err == 0) ? "" : " (incomplete: error above)");
	if (err == 0) {
		fprintf(stderr, "prof: `prof report %s` here, or scripts/prof-report.py on the host for symbols\n", dir);
	}
	free(chans);
	free(buf);

	return (err == 0) ? 0 : 1;
}
