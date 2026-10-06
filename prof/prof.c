/*
 * Phoenix-RTOS
 *
 * prof - system-wide profiler
 *
 * Records the kernel trace (perf_mode_trace) with thread sampling on, then summarizes where every
 * thread ran, what it waited for and for how long, who woke it, and which server threads its
 * messages waited on. The recording is the CTF trace psh `perf` writes, so it is also readable by
 * phoenix-rtos-hostutils/trace (convert.sh) and by the host-side symbolizing report.
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <stdio.h>
#include <string.h>

#include "prof.h"


static void usage(const char *progname)
{
	printf("Usage: %s record [-t secs] [-o dir] [-p pid] [-f period_us] [-d depth] [-s bytes] [-w bytes] [-r] [-L dirs]\n"
		   "       %s report [-p pid] [-n count] [dir]\n"
		   "record: trace every thread of every process for secs (default 10) into dir (default %s)\n"
		   "  -p pid     the process of interest (stored for report)\n"
		   "  -f us      sampling period per CPU (default 1000; the timer tick is the resolution)\n"
		   "  -d depth   frame-pointer chain length (default 16)\n"
		   "  -s bytes   user stack copied with each sample (default 512, 0..4096)\n"
		   "  -w bytes   user stack copied with each wait (default 512, 0..4096)\n"
		   "  -r         rolling: keep only what fits the kernel buffers, read it at the end\n"
		   "  -L dirs    where to look up the files the processes map, ':'-separated\n"
		   "report: CPU per process, top PCs per thread, waits by reason, longest waits and\n"
		   "  message edges (client -> server thread); addresses are symbolized on the host by\n"
		   "  scripts/prof-report.py\n",
		progname, progname, PROF_DEFAULT_DIR);
}


int main(int argc, char **argv)
{
	if (argc >= 2) {
		if (strcmp(argv[1], "record") == 0) {
			return prof_record(argc - 1, argv + 1);
		}
		if (strcmp(argv[1], "report") == 0) {
			return prof_report(argc - 1, argv + 1);
		}
	}

	usage(argv[0]);

	return 1;
}
