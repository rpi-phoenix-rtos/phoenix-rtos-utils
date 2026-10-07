/*
 * Phoenix-RTOS
 *
 * prof - system-wide profiler: the trace's event layouts
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include "prof.h"


#define RESYNC_RUN 6U


static const char *const eventNames[] = {
	[prof_ev_irqEnter - 0x20] = "interrupt_enter",
	[prof_ev_irqExit - 0x20] = "interrupt_exit",
	[prof_ev_scheduling - 0x20] = "thread_scheduling",
	[prof_ev_preempted - 0x20] = "thread_preempted",
	[prof_ev_enqueued - 0x20] = "thread_enqueued",
	[prof_ev_waking - 0x20] = "thread_waking",
	[prof_ev_threadCreate - 0x20] = "thread_create",
	[prof_ev_threadEnd - 0x20] = "thread_end",
	[prof_ev_syscallEnter - 0x20] = "syscall_enter",
	[prof_ev_syscallExit - 0x20] = "syscall_exit",
	[prof_ev_schedEnter - 0x20] = "sched_enter",
	[prof_ev_schedExit - 0x20] = "sched_exit",
	[prof_ev_lockName - 0x20] = "lock_name",
	[prof_ev_lockSetEnter - 0x20] = "lock_set_enter",
	[prof_ev_lockSetAcquired - 0x20] = "lock_set_acquired",
	[prof_ev_lockSetExit - 0x20] = "lock_set_exit",
	[prof_ev_lockClear - 0x20] = "lock_clear",
	[prof_ev_threadPriority - 0x20] = "thread_priority",
	[prof_ev_processKill - 0x20] = "process_kill",
	[prof_ev_processExec - 0x20] = "process_exec",
	[prof_ev_sample - 0x20] = "thread_sample",
	[prof_ev_wait - 0x20] = "thread_wait",
	[prof_ev_wakeup - 0x20] = "thread_wakeup",
	[prof_ev_msgSend - 0x20] = "msg_send",
	[prof_ev_msgRecv - 0x20] = "msg_recv",
	[prof_ev_msgRespond - 0x20] = "msg_respond",
	[prof_ev_traceStats - 0x20] = "trace_stats",
};


const char *prof_evName(uint8_t id)
{
	unsigned int idx = (unsigned int)id - 0x20U;

	if ((idx < sizeof(eventNames) / sizeof(eventNames[0])) && (eventNames[idx] != NULL)) {
		return eventNames[idx];
	}

	return "?";
}


const char *prof_exceptionName(unsigned int eclass)
{
	switch (eclass) {
		case 0x24U:
			return "data abort (page fault)";
		case 0x20U:
			return "instruction abort (page fault)";
		case 0x00U:
			return "undefined instruction";
		case 0x07U:
			return "FP/SIMD access";
		case 0x22U:
			return "PC alignment";
		case 0x26U:
			return "SP alignment";
		case 0x2cU:
			return "FP exception";
		case 0x3cU:
			return "BRK";
		default:
			return "exception";
	}
}


/* Size of the user part of thread_sample/thread_wait starting at offset o, 0 if truncated */
static size_t urecEnd(const uint8_t *p, size_t avail, size_t o)
{
	size_t nf, ns;

	if (avail < o + 33U) {
		return 0;
	}
	nf = p[o + 32U];
	o += 33U + nf * 8U;
	if (avail < o + 2U) {
		return 0;
	}
	ns = prof_rd16(p + o);
	o += 2U + ns * 8U;

	return (avail < o) ? 0U : o;
}


size_t prof_evSize(uint8_t id, const uint8_t *p, size_t avail)
{
	size_t sz;

	switch (id) {
		case prof_ev_irqEnter:
		case prof_ev_irqExit:
		case prof_ev_schedEnter:
		case prof_ev_schedExit:
			sz = 1;
			break;
		case prof_ev_scheduling:
		case prof_ev_preempted:
		case prof_ev_enqueued:
		case prof_ev_waking:
		case prof_ev_processKill:
			sz = 2;
			break;
		case prof_ev_syscallEnter:
		case prof_ev_syscallExit:
		case prof_ev_threadPriority:
			sz = 3;
			break;
		case prof_ev_threadEnd:
			sz = 4;
			break;
		case prof_ev_wakeup:
			sz = 5;
			break;
		case prof_ev_lockSetEnter:
		case prof_ev_lockSetAcquired:
		case prof_ev_lockSetExit:
		case prof_ev_lockClear:
			sz = 6;
			break;
		case prof_ev_traceStats:
			sz = 8;
			break;
		case prof_ev_msgRespond:
			sz = 10;
			break;
		case prof_ev_msgRecv:
			sz = 12;
			break;
		case prof_ev_msgSend:
			sz = 14;
			break;
		case prof_ev_lockName:
			sz = 20;
			break;
		case prof_ev_threadCreate:
		case prof_ev_processExec:
			sz = 133;
			break;
		case prof_ev_sample:
			return (avail < PROF_SAMPLE_KFRAMES) ? 0U : urecEnd(p, avail, PROF_SAMPLE_KFRAMES + (size_t)p[PROF_SAMPLE_NK] * 8U);
		case prof_ev_wait:
			return (avail < PROF_WAIT_KFRAMES) ? 0U : urecEnd(p, avail, PROF_WAIT_KFRAMES + (size_t)p[PROF_WAIT_NK] * 8U);
		default:
			return 0;
	}

	return (avail < sz) ? 0U : sz;
}


/*
 * A rolling trace (prof record -r) discards whole bytes, not events, so a stream may begin in the
 * middle of one. o is taken as an event boundary if RESYNC_RUN events parse from it back to back
 * (known ids, sizes that fit, time not going back), or all events up to the end of the stream do.
 */
int prof_syncAt(const uint8_t *data, size_t sz, size_t o)
{
	unsigned int n = 0;
	uint32_t prev = 0, ts;
	size_t psz;

	while (n < RESYNC_RUN) {
		if (o == sz) {
			return (n > 0U) ? 1 : 0;
		}
		if (o + 5U > sz) {
			return 0;
		}
		ts = prof_rd32(data + o);
		psz = prof_evSize(data[o + 4U], data + o + 5U, sz - o - 5U);
		if ((psz == 0U) || ((n > 0U) && (ts < prev))) {
			return 0;
		}
		prev = ts;
		n++;
		o += 5U + psz;
	}

	return 1;
}


void prof_mixAdd(prof_mix_t *mix, const uint8_t *data, size_t sz, int cpu)
{
	size_t o = 0, psz;
	int synced = 0;
	uint8_t id;

	if ((cpu < 0) || (cpu >= PROF_MAX_CPUS)) {
		return;
	}

	while (o + 5U <= sz) {
		if ((synced == 0) || (prof_evSize(data[o + 4U], data + o + 5U, sz - o - 5U) == 0U)) {
			while ((o + 5U <= sz) && (prof_syncAt(data, sz, o) == 0)) {
				o++;
				mix->skipped++;
			}
			if (o + 5U > sz) {
				break;
			}
		}
		synced = 1;
		id = data[o + 4U];
		psz = prof_evSize(id, data + o + 5U, sz - o - 5U);
		mix->count[id][cpu]++;
		mix->bytes[id][cpu] += 5U + psz;
		if (id == prof_ev_traceStats) {
			mix->stats = 1;
			mix->discarded += prof_rd32(data + o + 5U);
			mix->waitsDropped += prof_rd32(data + o + 9U);
		}
		o += 5U + psz;
	}
}


void prof_mixPrint(FILE *f, const prof_mix_t *mix, int ncpus, double secs)
{
	uint64_t total = 0, n, b, best;
	int shown[256] = { 0 };
	unsigned int i, pick;
	int c;

	ncpus = (ncpus > PROF_MAX_CPUS) ? PROF_MAX_CPUS : ncpus;

	for (i = 0; i < 256U; i++) {
		for (c = 0; c < ncpus; c++) {
			total += mix->bytes[i][c];
		}
	}

	fprintf(f, "\nEvent mix: %.2f MB in %.1f s (%.2f MB/s)\n", (double)total / 1048576.0, secs,
		(secs > 0.0) ? (double)total / 1048576.0 / secs : 0.0);
	fprintf(f, "  %-18s %9s %9s %6s", "event", "count", "KB", "%");
	for (c = 0; c < ncpus; c++) {
		fprintf(f, "   cpu%d KB", c);
	}
	fprintf(f, "\n");

	for (;;) {
		for (i = 0, pick = 256U, best = 0; i < 256U; i++) {
			for (c = 0, b = 0; c < ncpus; c++) {
				b += mix->bytes[i][c];
			}
			if ((shown[i] == 0) && (b > best)) {
				best = b;
				pick = i;
			}
		}
		if (pick == 256U) {
			break;
		}
		shown[pick] = 1;
		for (c = 0, n = 0; c < ncpus; c++) {
			n += mix->count[pick][c];
		}
		fprintf(f, "  %-18s %9llu %9.1f %5.1f%%", prof_evName((uint8_t)pick), (unsigned long long)n, (double)best / 1024.0,
			100.0 * (double)best / (double)((total != 0U) ? total : 1U));
		for (c = 0; c < ncpus; c++) {
			fprintf(f, " %9.1f", (double)mix->bytes[pick][c] / 1024.0);
		}
		fprintf(f, "\n");
	}

	if (mix->skipped != 0U) {
		fprintf(f, "  (%llu bytes were not whole events: a rolling trace starts mid-event)\n", (unsigned long long)mix->skipped);
	}
	if (mix->stats != 0) {
		fprintf(f, "Lost: %llu events (a full channel), %llu waits (no free wait slot)%s\n", (unsigned long long)mix->discarded,
			(unsigned long long)mix->waitsDropped, ((mix->discarded | mix->waitsDropped) == 0U) ? ": the trace is complete" : "");
	}
	else {
		fprintf(f, "Lost: not known (no trace_stats event: an older kernel, or the trace was not stopped)\n");
	}
}
