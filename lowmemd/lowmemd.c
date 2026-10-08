/*
 * Phoenix-RTOS
 *
 * lowmemd - low memory monitor; optionally stops the process using the most memory
 *
 * Phoenix-RTOS has no out-of-memory handling: once the page allocator is empty every allocation
 * fails at once, in servers and programs alike. lowmemd watches the free memory and reports the
 * processes using the most of it; with -k it kills the largest one when the free memory drops
 * below a reserve, before the allocations start failing. It is started by nothing: run it by
 * hand or from a session script.
 *
 * Free memory is the kernel's page counter (meminfo()), which includes the file cache the kernel
 * gives up on demand. A process's size is the anonymous memory of its map entries (what the
 * panel's memory plugin and WebKit's footprint count); buffers shared through objects (GPU,
 * shared memory, contiguous DMA) are not counted against anyone.
 *
 * Every buffer is static and touched at start, so a scan or a kill needs no memory at the moment
 * there is none.
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/threads.h>


#define LOWMEMD_THREADS   2048
#define LOWMEMD_ENTRIES   4096
#define LOWMEMD_PROTECTED 16
#define LOWMEMD_TOP_MAX   16

#define MIB (1024ULL * 1024ULL)


typedef struct {
	pid_t pid;
	unsigned long long anon;
	const char *name;
} lowmemd_proc_t;


static struct {
	/* options */
	unsigned int intervalMs;
	unsigned int reportSecs;
	unsigned long long warning;
	unsigned long long critical;
	unsigned long long reserve; /* kill below this much free memory; 0: never kill */
	unsigned long long minVictim;
	unsigned int cooldownSecs;
	unsigned int ntop;
	const char *spared[LOWMEMD_PROTECTED];
	unsigned int nspared;
	int logfd;

	/* state */
	unsigned long long total;
	unsigned long long free;
	unsigned int truncatedThreads;
	unsigned int truncatedEntries;

	threadinfo_t threads[LOWMEMD_THREADS];
	entryinfo_t entries[LOWMEMD_ENTRIES];
	lowmemd_proc_t procs[LOWMEMD_THREADS];
	unsigned int nprocs;
	char line[1024];
} lowmemd_common;


static double lowmemd_now(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}


/* One line with write(): stdio may allocate, and the line must get out when nothing else can */
static void lowmemd_log(const char *fmt, ...)
{
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(lowmemd_common.line, sizeof(lowmemd_common.line) - 1U, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return;
	}
	if ((size_t)len > sizeof(lowmemd_common.line) - 2U) {
		len = (int)sizeof(lowmemd_common.line) - 2;
	}
	lowmemd_common.line[len++] = '\n';
	(void)write(lowmemd_common.logfd, lowmemd_common.line, (size_t)len);
}


static int lowmemd_readSystem(void)
{
	meminfo_t info;

	memset(&info, 0, sizeof(info));
	info.page.mapsz = -1;
	info.entry.mapsz = -1;
	info.entry.kmapsz = -1;
	info.maps.mapsz = -1;
	meminfo(&info);

	/* the kernel always sets page.sz (sizeof(page_t)): zero means the call did nothing */
	if (info.page.sz == 0U) {
		return -1;
	}

	/* unsigned int byte counts: they wrap above 4 GiB of RAM (a 4 GB Pi 4 manages 3.8 GiB) */
	lowmemd_common.free = info.page.free;
	lowmemd_common.total = (unsigned long long)info.page.free + info.page.alloc;
	return 0;
}


/* The anonymous memory of a process's map entries */
static unsigned long long lowmemd_processAnon(pid_t pid)
{
	meminfo_t info;
	unsigned long long sum = 0;
	int i, n;

	memset(&info, 0, sizeof(info));
	info.page.mapsz = -1;
	info.entry.kmapsz = -1;
	info.maps.mapsz = -1;
	info.entry.pid = (unsigned int)pid;
	info.entry.mapsz = LOWMEMD_ENTRIES;
	info.entry.map = lowmemd_common.entries;
	meminfo(&info);

	if (info.entry.mapsz < 0) {
		return 0;
	}

	n = info.entry.mapsz;
	if (n > LOWMEMD_ENTRIES) {
		/* more entries than room: the sum covers the first LOWMEMD_ENTRIES */
		lowmemd_common.truncatedEntries++;
		n = LOWMEMD_ENTRIES;
	}

	for (i = 0; i < n; i++) {
		/* (size_t)-1: an entry with no anonymous pages (the kernel may store it as ~0U) */
		if ((lowmemd_common.entries[i].anonsz != SIZE_MAX) && (lowmemd_common.entries[i].anonsz != (size_t)~0U)) {
			sum += lowmemd_common.entries[i].anonsz;
		}
	}

	return sum;
}


/* The program's name: the kernel gives the whole command line (process_getName()), so the first
 * word, without its directory (an argument such as a URL has slashes too) */
static const char *lowmemd_programName(char *name)
{
	char *space = strchr(name, ' ');
	const char *slash;

	if (space != NULL) {
		*space = '\0';
	}
	slash = strrchr(name, '/');

	return (slash != NULL) ? slash + 1 : name;
}


/* Every process (once, at its first thread) with its anonymous memory, largest first */
static int lowmemd_scan(void)
{
	lowmemd_proc_t tmp;
	unsigned int i, j, n;
	int ret;
	pid_t pid;

	ret = threadsinfo(LOWMEMD_THREADS, PH_THREADINFO_NAME, lowmemd_common.threads);
	if (ret < 0) {
		return -1;
	}
	n = (unsigned int)ret;
	if (n > LOWMEMD_THREADS) {
		lowmemd_common.truncatedThreads++;
		n = LOWMEMD_THREADS;
	}

	lowmemd_common.nprocs = 0;
	for (i = 0; i < n; i++) {
		pid = lowmemd_common.threads[i].pid;
		/* pid 0: the kernel's own threads */
		if (pid <= 0) {
			continue;
		}
		for (j = 0; j < lowmemd_common.nprocs; j++) {
			if (lowmemd_common.procs[j].pid == pid) {
				break;
			}
		}
		if (j < lowmemd_common.nprocs) {
			continue;
		}

		lowmemd_common.threads[i].name[sizeof(lowmemd_common.threads[i].name) - 1U] = '\0';
		lowmemd_common.procs[lowmemd_common.nprocs].pid = pid;
		lowmemd_common.procs[lowmemd_common.nprocs].name = lowmemd_programName(lowmemd_common.threads[i].name);
		lowmemd_common.procs[lowmemd_common.nprocs].anon = lowmemd_processAnon(pid);
		lowmemd_common.nprocs++;
	}

	/* insertion sort, largest first (a few hundred processes at most) */
	for (i = 1; i < lowmemd_common.nprocs; i++) {
		tmp = lowmemd_common.procs[i];
		for (j = i; (j > 0U) && (lowmemd_common.procs[j - 1U].anon < tmp.anon); j--) {
			lowmemd_common.procs[j] = lowmemd_common.procs[j - 1U];
		}
		lowmemd_common.procs[j] = tmp;
	}

	return 0;
}


static int lowmemd_isAlive(pid_t pid)
{
	int i, n;

	n = threadsinfo(LOWMEMD_THREADS, 0, lowmemd_common.threads);
	if (n > LOWMEMD_THREADS) {
		n = LOWMEMD_THREADS;
	}
	for (i = 0; i < n; i++) {
		if (lowmemd_common.threads[i].pid == pid) {
			return 1;
		}
	}

	return 0;
}


static void lowmemd_report(double t, const char *why)
{
	char top[512];
	size_t len = 0;
	unsigned int i;
	int ret;

	top[0] = '\0';
	if (lowmemd_scan() == 0) {
		for (i = 0; (i < lowmemd_common.ntop) && (i < lowmemd_common.nprocs); i++) {
			ret = snprintf(top + len, sizeof(top) - len, "%s%d:%s:%llu", (i == 0U) ? "" : ",", (int)lowmemd_common.procs[i].pid,
				lowmemd_common.procs[i].name, lowmemd_common.procs[i].anon / MIB);
			if ((ret < 0) || ((size_t)ret >= sizeof(top) - len)) {
				break;
			}
			len += (size_t)ret;
		}
	}

	lowmemd_log("LOWMEMD t=%.0f %s free_mb=%llu total_mb=%llu top=%s", t, why, lowmemd_common.free / MIB, lowmemd_common.total / MIB,
		(top[0] != '\0') ? top : "-");
}


static int lowmemd_isSpared(const lowmemd_proc_t *proc)
{
	unsigned int i;

	if ((proc->pid == getpid()) || (proc->pid == 1)) {
		return 1;
	}
	for (i = 0; i < lowmemd_common.nspared; i++) {
		if (strcmp(proc->name, lowmemd_common.spared[i]) == 0) {
			return 1;
		}
	}

	return 0;
}


/* Kills the largest process that may be killed; its pid, or -1 */
static pid_t lowmemd_killLargest(double t)
{
	const lowmemd_proc_t *victim = NULL;
	unsigned int i;

	if (lowmemd_scan() < 0) {
		lowmemd_log("LOWMEMD t=%.0f kill none: the processes could not be listed", t);
		return -1;
	}

	for (i = 0; i < lowmemd_common.nprocs; i++) {
		if (lowmemd_common.procs[i].anon < lowmemd_common.minVictim) {
			break;
		}
		if (lowmemd_isSpared(&lowmemd_common.procs[i]) == 0) {
			victim = &lowmemd_common.procs[i];
			break;
		}
	}

	if (victim == NULL) {
		lowmemd_log("LOWMEMD t=%.0f kill none: no process above %llu MB may be killed (free_mb=%llu)", t, lowmemd_common.minVictim / MIB,
			lowmemd_common.free / MIB);
		return -1;
	}

	/* SIGKILL, not SIGTERM: a handler would need memory there is none of */
	if (kill(victim->pid, SIGKILL) < 0) {
		lowmemd_log("LOWMEMD t=%.0f kill pid=%d name=%s failed: %s", t, (int)victim->pid, victim->name, strerror(errno));
		return -1;
	}
	lowmemd_log("LOWMEMD t=%.0f kill pid=%d name=%s anon_mb=%llu free_mb=%llu reserve_mb=%llu", t, (int)victim->pid, victim->name,
		victim->anon / MIB, lowmemd_common.free / MIB, lowmemd_common.reserve / MIB);

	return victim->pid;
}


static const char *lowmemd_level(void)
{
	if (lowmemd_common.free < lowmemd_common.critical) {
		return "critical";
	}
	if (lowmemd_common.free < lowmemd_common.warning) {
		return "warning";
	}
	return "normal";
}


static void lowmemd_usage(const char *progname)
{
	printf("Usage: %s [options]\n", progname);
	printf("  -i ms     poll the free memory every ms milliseconds (default 1000)\n");
	printf("  -r s      report the largest processes every s seconds (default 30, 0: only on events)\n");
	printf("  -w MB     warning level (default 20 %% of RAM)\n");
	printf("  -c MB     critical level (default 10 %% of RAM, at least 300 MB)\n");
	printf("  -k MB     kill the largest process when less than MB are free (default: never kill)\n");
	printf("  -m MB     only a process with at least MB of anonymous memory may be killed (default 128)\n");
	printf("  -d s      after a kill, wait s seconds for its memory before the next one (default 10)\n");
	printf("  -x name   never kill a program of this name (repeatable)\n");
	printf("  -t N      how many processes a report lists (default 5)\n");
	printf("  -l path   log to path, e.g. /dev/console (default: standard error)\n");
}


int main(int argc, char *argv[])
{
	unsigned long long warningMB = 0, criticalMB = 0;
	const char *lastLevel = NULL, *level;
	double t0, now, nextReport, killAt = 0, cooldownUntil = 0;
	unsigned long long freeAtKill = 0;
	pid_t victim = -1;
	int c;

	lowmemd_common.intervalMs = 1000;
	lowmemd_common.reportSecs = 30;
	lowmemd_common.minVictim = 128 * MIB;
	lowmemd_common.cooldownSecs = 10;
	lowmemd_common.ntop = 5;
	lowmemd_common.logfd = STDERR_FILENO;

	while ((c = getopt(argc, argv, "i:r:w:c:k:m:d:x:t:l:h")) != -1) {
		switch (c) {
			case 'i':
				lowmemd_common.intervalMs = (unsigned int)strtoul(optarg, NULL, 10);
				break;
			case 'r':
				lowmemd_common.reportSecs = (unsigned int)strtoul(optarg, NULL, 10);
				break;
			case 'w':
				warningMB = strtoull(optarg, NULL, 10);
				break;
			case 'c':
				criticalMB = strtoull(optarg, NULL, 10);
				break;
			case 'k':
				lowmemd_common.reserve = strtoull(optarg, NULL, 10) * MIB;
				break;
			case 'm':
				lowmemd_common.minVictim = strtoull(optarg, NULL, 10) * MIB;
				break;
			case 'd':
				lowmemd_common.cooldownSecs = (unsigned int)strtoul(optarg, NULL, 10);
				break;
			case 'x':
				if (lowmemd_common.nspared < LOWMEMD_PROTECTED) {
					lowmemd_common.spared[lowmemd_common.nspared++] = optarg;
				}
				break;
			case 't':
				lowmemd_common.ntop = (unsigned int)strtoul(optarg, NULL, 10);
				if (lowmemd_common.ntop > LOWMEMD_TOP_MAX) {
					lowmemd_common.ntop = LOWMEMD_TOP_MAX;
				}
				break;
			case 'l':
				lowmemd_common.logfd = open(optarg, O_WRONLY | O_APPEND | O_CREAT, 0644);
				if (lowmemd_common.logfd < 0) {
					fprintf(stderr, "lowmemd: %s: %s\n", optarg, strerror(errno));
					return EXIT_FAILURE;
				}
				break;
			case 'h':
			default:
				lowmemd_usage(argv[0]);
				return (c == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}

	if (lowmemd_common.intervalMs < 100U) {
		lowmemd_common.intervalMs = 100;
	}

	if (lowmemd_readSystem() < 0) {
		fprintf(stderr, "lowmemd: meminfo() failed\n");
		return EXIT_FAILURE;
	}

	lowmemd_common.warning = (warningMB != 0U) ? warningMB * MIB : lowmemd_common.total / 5U;
	lowmemd_common.critical = (criticalMB != 0U) ? criticalMB * MIB : lowmemd_common.total / 10U;
	if ((criticalMB == 0U) && (lowmemd_common.critical < 300U * MIB)) {
		lowmemd_common.critical = 300U * MIB;
	}

	/* make every buffer resident now, while there is memory: a scan must not fault later */
	memset(lowmemd_common.threads, 0, sizeof(lowmemd_common.threads));
	memset(lowmemd_common.entries, 0, sizeof(lowmemd_common.entries));
	memset(lowmemd_common.procs, 0, sizeof(lowmemd_common.procs));
	(void)lowmemd_scan();

	t0 = lowmemd_now();
	lowmemd_log("LOWMEMD t=0 start pid=%d total_mb=%llu free_mb=%llu warning_mb=%llu critical_mb=%llu kill_below_mb=%llu min_victim_mb=%llu",
		(int)getpid(), lowmemd_common.total / MIB, lowmemd_common.free / MIB, lowmemd_common.warning / MIB, lowmemd_common.critical / MIB,
		lowmemd_common.reserve / MIB, lowmemd_common.minVictim / MIB);
	nextReport = 0;

	for (;;) {
		now = lowmemd_now() - t0;
		if (lowmemd_readSystem() == 0) {
			level = lowmemd_level();
			if (level != lastLevel) {
				lowmemd_report(now, level);
				lastLevel = level;
			}
			else if ((lowmemd_common.reportSecs != 0U) && (now >= nextReport)) {
				lowmemd_report(now, "report");
			}
			if ((lowmemd_common.reportSecs != 0U) && (now >= nextReport)) {
				nextReport = now + lowmemd_common.reportSecs;
			}

			/* what the last kill gave back, once its cooldown is over */
			if ((victim > 0) && (now >= cooldownUntil)) {
				lowmemd_log("LOWMEMD t=%.0f after-kill pid=%d gone=%d free_mb=%llu was_mb=%llu after_s=%.0f", now, (int)victim,
					(lowmemd_isAlive(victim) == 0) ? 1 : 0, lowmemd_common.free / MIB, freeAtKill / MIB, now - killAt);
				victim = -1;
			}

			if ((lowmemd_common.reserve != 0U) && (lowmemd_common.free < lowmemd_common.reserve) && (now >= cooldownUntil)) {
				freeAtKill = lowmemd_common.free;
				victim = lowmemd_killLargest(now);
				killAt = now;
				cooldownUntil = now + lowmemd_common.cooldownSecs;
			}
		}

		(void)usleep(lowmemd_common.intervalMs * 1000U);
	}

	return EXIT_SUCCESS;
}
