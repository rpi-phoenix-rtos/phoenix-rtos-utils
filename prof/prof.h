/*
 * Phoenix-RTOS
 *
 * prof - system-wide profiler
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef _PROF_H_
#define _PROF_H_

#include <stddef.h>
#include <stdint.h>


#define PROF_DEFAULT_DIR "/tmp/prof"


/* Trace event ids, mirror phoenix-rtos-kernel/perf/tsdl/metadata */
enum {
	prof_ev_irqEnter = 0x20,
	prof_ev_irqExit = 0x21,
	prof_ev_scheduling = 0x22,
	prof_ev_preempted = 0x23,
	prof_ev_enqueued = 0x24,
	prof_ev_waking = 0x25,
	prof_ev_threadCreate = 0x26,
	prof_ev_threadEnd = 0x27,
	prof_ev_syscallEnter = 0x28,
	prof_ev_syscallExit = 0x29,
	prof_ev_schedEnter = 0x2a,
	prof_ev_schedExit = 0x2b,
	prof_ev_lockName = 0x2c,
	prof_ev_lockSetEnter = 0x2d,
	prof_ev_lockSetAcquired = 0x2e,
	prof_ev_lockSetExit = 0x2f,
	prof_ev_lockClear = 0x30,
	prof_ev_threadPriority = 0x31,
	prof_ev_processKill = 0x32,
	prof_ev_processExec = 0x33,
	prof_ev_sample = 0x40,
	prof_ev_wait = 0x41,
	prof_ev_wakeup = 0x42,
	prof_ev_msgSend = 0x43,
	prof_ev_msgRecv = 0x44,
	prof_ev_msgRespond = 0x45,
};


/* Written by `prof record` next to the trace channels */
#define PROF_INFO_FILE "prof.info"


int prof_record(int argc, char **argv);


int prof_report(int argc, char **argv);


#endif
