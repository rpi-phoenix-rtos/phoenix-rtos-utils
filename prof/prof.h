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
#include <stdio.h>


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
	prof_ev_traceStats = 0x46,
};


/* Payload offsets of thread_sample and thread_wait (the user part follows the kernel frames) */
#define PROF_SAMPLE_MODE    2U
#define PROF_SAMPLE_KFLAGS  3U
#define PROF_SAMPLE_KPC     4U
#define PROF_SAMPLE_KLR     12U
#define PROF_SAMPLE_SYSCALL 20U
#define PROF_SAMPLE_ECLASS  22U
#define PROF_SAMPLE_KFAR    23U
#define PROF_SAMPLE_NK      31U
#define PROF_SAMPLE_KFRAMES 32U

#define PROF_SAMPLE_SKID  (1U << 0) /* kflags: kpc follows an interrupt unmask, the work was before it */
#define PROF_WAIT_REPEAT  (1U << 3) /* thread_wait flags: frames and stack as the thread's previous wait */
#define PROF_WAIT_FLAGS     2U
#define PROF_WAIT_QUEUE     3U
#define PROF_WAIT_TIMEOUT   7U
#define PROF_WAIT_BLOCKED   11U
#define PROF_WAIT_SYSCALL   15U
#define PROF_WAIT_ARGS      17U
#define PROF_WAIT_NK        49U
#define PROF_WAIT_KFRAMES   50U

#define PROF_MAX_CPUS 16


/* Bytes and counts per event type and CPU, and what trace_stats said was lost */
typedef struct {
	uint64_t count[256][PROF_MAX_CPUS];
	uint64_t bytes[256][PROF_MAX_CPUS];
	uint64_t skipped;
	int stats;
	uint64_t discarded, waitsDropped;
} prof_mix_t;


static inline uint16_t prof_rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}


static inline uint32_t prof_rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}


static inline uint64_t prof_rd64(const uint8_t *p)
{
	return (uint64_t)prof_rd32(p) | ((uint64_t)prof_rd32(p + 4) << 32);
}


const char *prof_evName(uint8_t id);


/* Name of an exception class (ESR.EC) a thread enters the kernel with */
const char *prof_exceptionName(unsigned int eclass);


/* Payload size of an event, 0 if unknown or truncated */
size_t prof_evSize(uint8_t id, const uint8_t *p, size_t avail);


/* Whether an event boundary is at offset o (a run of events parses from it) */
int prof_syncAt(const uint8_t *data, size_t sz, size_t o);


/* Adds a channel's (or part of a channel's) events to mix */
void prof_mixAdd(prof_mix_t *mix, const uint8_t *data, size_t sz, int cpu);


void prof_mixPrint(FILE *f, const prof_mix_t *mix, int ncpus, double secs);


/* Written by `prof record` next to the trace channels */
#define PROF_INFO_FILE "prof.info"


int prof_record(int argc, char **argv);


int prof_report(int argc, char **argv);


#endif
