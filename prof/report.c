/*
 * Phoenix-RTOS
 *
 * prof - system-wide profiler: on-target summary of a recording
 *
 * Reads the raw CTF channels written by `prof record` (or psh `perf -m trace`), merges the CPU
 * streams by time and prints CPU use per process, the hottest PCs per thread, the waits of every
 * thread grouped by reason, the longest single waits and the message edges between clients and
 * the server threads that served them. Addresses are printed raw: symbolize them on the host
 * (scripts/prof-report.py does it and folds stacks for flame graphs).
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <phoenix/syscalls.h>

#include "prof.h"


#define NTIDS     65536U
#define NLONGEST  64U
#define NPROCS    1024U
#define NAME_LEN  48U
#define CAUSES    5U /* thread_wakeup causes 0..3, 4: none seen (exit, kill) */
#define NO_SYSCALL (-1)


#define SYSCALL_NAME(n) #n,
static const char *const syscallNames[] = { SYSCALLS(SYSCALL_NAME) };
#define NSYSCALLS ((int)(sizeof(syscallNames) / sizeof(syscallNames[0])))

static const char *const causeNames[CAUSES] = { "wakeup", "timeout", "signal", "lock", "other" };


/* One event of the merged streams */
typedef struct {
	uint32_t ts;
	uint32_t seq;
	uint8_t id;
	uint8_t cpu;
	uint32_t len;
	const uint8_t *p;
} ev_t;


/* User part of thread_sample/thread_wait */
typedef struct {
	uint64_t pc, lr, sp, fp;
	unsigned int nframes;
	const uint8_t *frames;
	unsigned int nstack;
	const uint8_t *stack;
} urec_t;


typedef struct {
	int pid;
	char name[NAME_LEN];
	uint32_t samples[3]; /* by thread_sample mode */
	int syscall;         /* in flight, NO_SYSCALL if not known */
	uint32_t msgMid;     /* last msg_send of the syscall in flight */
	uint32_t msgPort;
	uint32_t msgType;

	int waiting;
	uint32_t waitTs;
	uint8_t waitFlags;
	int waitSyscall;
	uint64_t waitObj;
	uint32_t waitTimeout;
	uint32_t waitMid;
	uint64_t waitPc;
	int wakeCause; /* from thread_wakeup, until thread_waking ends the wait */
	int waker;
} thr_t;


typedef struct {
	int tid;
	int syscall;
	uint64_t obj;
	uint32_t count;
	uint64_t totalUs;
	uint32_t maxUs;
	uint32_t causes[CAUSES];
	int lastWaker;
} waitagg_t;


typedef struct {
	int client;
	int server;
	uint32_t port;
	uint32_t count;
	uint64_t totalUs;
	uint32_t maxUs;
} edge_t;


typedef struct {
	uint32_t mid;
	int client;
	int server;
	uint32_t port;
} inflight_t;


typedef struct {
	int tid;
	int syscall;
	uint64_t obj;
	uint32_t startTs;
	uint32_t us;
	uint32_t timeout;
	int cause;
	int waker;
	int existing;
	int open;
	uint64_t pc;
} longwait_t;


typedef struct {
	uint64_t key;
	uint32_t count;
} pchist_t;


static struct {
	ev_t *evs;
	size_t nevs, capevs;
	uint8_t **files;
	size_t nfiles;
	int ncpus;
	int pidFilter;
	unsigned int top;
	uint32_t lastTs;

	thr_t *thr[NTIDS];

	pchist_t *pcs;
	size_t npcs, cappcs;

	waitagg_t *waits;
	size_t nwaits, capwaits;

	edge_t *edges;
	size_t nedges, capedges;

	inflight_t *msgs;
	size_t nmsgs, capmsgs;

	longwait_t longest[NLONGEST];
	size_t nlongest;

	uint64_t nsamples[3];
	uint64_t nwaitEvents;
	int selfPid;

	uint64_t evCount[256], evBytes[256];
} rep;


static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}


static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}


static uint64_t rd64(const uint8_t *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}


static uint64_t hash64(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	return x;
}


/* Size of the user part starting at offset o, 0 if truncated */
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
	ns = rd16(p + o);
	o += 2U + ns * 8U;

	return (avail < o) ? 0U : o;
}


static void urecParse(const uint8_t *p, size_t o, urec_t *u)
{
	u->pc = rd64(p + o);
	u->lr = rd64(p + o + 8U);
	u->sp = rd64(p + o + 16U);
	u->fp = rd64(p + o + 24U);
	u->nframes = p[o + 32U];
	u->frames = p + o + 33U;
	o += 33U + (size_t)u->nframes * 8U;
	u->nstack = rd16(p + o);
	u->stack = p + o + 2U;
}


/* Payload size of an event, 0 if unknown or truncated */
static size_t evSize(uint8_t id, const uint8_t *p, size_t avail)
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
			return (avail < 12U) ? 0U : urecEnd(p, avail, 12U + (size_t)p[11] * 8U);
		case prof_ev_wait:
			return (avail < 48U) ? 0U : urecEnd(p, avail, 48U + (size_t)p[47] * 8U);
		default:
			return 0;
	}

	return (avail < sz) ? 0U : sz;
}


static int evPush(const ev_t *ev)
{
	ev_t *n;

	if (rep.nevs == rep.capevs) {
		rep.capevs = (rep.capevs == 0U) ? 65536U : rep.capevs * 2U;
		n = realloc(rep.evs, rep.capevs * sizeof(*n));
		if (n == NULL) {
			return -ENOMEM;
		}
		rep.evs = n;
	}
	rep.evs[rep.nevs++] = *ev;

	return 0;
}


static uint8_t *readFile(const char *path, size_t *sz)
{
	FILE *f = fopen(path, "rb");
	uint8_t *data = NULL, *n;
	size_t cap = 0, len = 0, got;

	if (f == NULL) {
		return NULL;
	}

	for (;;) {
		if (len == cap) {
			cap = (cap == 0U) ? (1U << 20) : cap * 2U;
			n = realloc(data, cap);
			if (n == NULL) {
				free(data);
				fclose(f);
				return NULL;
			}
			data = n;
		}
		got = fread(data + len, 1, cap - len, f);
		if (got == 0U) {
			break;
		}
		len += got;
	}

	fclose(f);
	*sz = len;

	return data;
}


/*
 * A rolling trace (prof record -r) discards whole bytes, not events, so a stream may begin in the
 * middle of one. o is taken as an event boundary if RESYNC_RUN events parse from it back to back
 * (known ids, sizes that fit, time not going back), or all events up to the end of the stream do.
 */
#define RESYNC_RUN 6U

static int syncAt(const uint8_t *data, size_t sz, size_t o)
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
		ts = rd32(data + o);
		psz = evSize(data[o + 4U], data + o + 5U, sz - o - 5U);
		if ((psz == 0U) || ((n > 0U) && (ts < prev))) {
			return 0;
		}
		prev = ts;
		n++;
		o += 5U + psz;
	}

	return 1;
}


static int loadStream(const char *path, int cpu)
{
	uint8_t *data, **files;
	size_t sz = 0, o = 0, psz, skipped = 0, start;
	int sync = 1;
	ev_t ev;

	data = readFile(path, &sz);
	if (data == NULL) {
		return -ENOENT;
	}

	files = realloc(rep.files, (rep.nfiles + 1U) * sizeof(*files));
	if (files == NULL) {
		free(data);
		return -ENOMEM;
	}
	rep.files = files;
	rep.files[rep.nfiles++] = data;

	while (o + 5U <= sz) {
		if (sync != 0) {
			for (start = o; (o + 5U <= sz) && (syncAt(data, sz, o) == 0); o++) {
			}
			skipped += o - start;
			sync = 0;
			if (o + 5U > sz) {
				break;
			}
		}
		ev.ts = rd32(data + o);
		ev.id = data[o + 4U];
		ev.cpu = (uint8_t)cpu;
		psz = evSize(ev.id, data + o + 5U, sz - o - 5U);
		if (psz == 0U) {
			sync = 1;
			continue;
		}
		ev.p = data + o + 5U;
		ev.len = (uint32_t)psz;
		rep.evCount[ev.id]++;
		rep.evBytes[ev.id] += 5U + psz;
		ev.seq = (uint32_t)rep.nevs;
		if (evPush(&ev) < 0) {
			return -ENOMEM;
		}
		o += 5U + psz;
	}

	if (skipped != 0U) {
		fprintf(stderr, "prof: %s: skipped %zu bytes that are not whole events (a rolling trace starts mid-event)\n", path, skipped);
	}

	return 0;
}


static int evCmp(const void *a, const void *b)
{
	const ev_t *x = a, *y = b;

	if (x->ts != y->ts) {
		return (x->ts < y->ts) ? -1 : 1;
	}
	return (x->seq < y->seq) ? -1 : ((x->seq > y->seq) ? 1 : 0);
}


/* Thread table */


static thr_t *thrGet(int tid)
{
	thr_t *t;

	if ((tid < 0) || ((unsigned int)tid >= NTIDS)) {
		return NULL;
	}

	t = rep.thr[tid];
	if (t == NULL) {
		t = calloc(1, sizeof(*t));
		if (t == NULL) {
			return NULL;
		}
		t->pid = -1;
		t->syscall = NO_SYSCALL;
		t->waker = -1;
		snprintf(t->name, sizeof(t->name), "?");
		rep.thr[tid] = t;
	}

	return t;
}


/* "path arg..." -> basename of path */
static void thrSetName(thr_t *t, int pid, const char *name, size_t len)
{
	const char *start = name, *end = name, *s;
	size_t n;

	for (s = name; (s < name + len) && (*s != '\0') && (*s != ' '); s++) {
		if (*s == '/') {
			start = s + 1;
		}
		end = s + 1;
	}

	n = (size_t)(end - start);
	if (n >= sizeof(t->name)) {
		n = sizeof(t->name) - 1U;
	}
	if (n != 0U) {
		memcpy(t->name, start, n);
		t->name[n] = '\0';
	}
	t->pid = pid;
}


static const char *thrName(int tid)
{
	thr_t *t = ((tid >= 0) && ((unsigned int)tid < NTIDS)) ? rep.thr[tid] : NULL;

	return (t != NULL) ? t->name : "?";
}


static int thrPid(int tid)
{
	thr_t *t = ((tid >= 0) && ((unsigned int)tid < NTIDS)) ? rep.thr[tid] : NULL;

	return (t != NULL) ? t->pid : -1;
}


/* The recorder's own threads are left out: they only drain the trace */
static int thrSelected(int tid)
{
	int pid = thrPid(tid);

	if ((rep.selfPid > 0) && (pid == rep.selfPid)) {
		return 0;
	}

	return (rep.pidFilter <= 0) || (pid == rep.pidFilter);
}


/* Generic open-addressing tables */


static void *tableFind(void *table, size_t cap, size_t elemSz, uint64_t h, int (*match)(const void *e, const void *key), const void *key, int *found)
{
	size_t i = (size_t)h & (cap - 1U);
	uint8_t *e;

	for (;;) {
		e = (uint8_t *)table + i * elemSz;
		if (*(const uint64_t *)(const void *)e == 0U) {
			*found = 0;
			return e;
		}
		if (match(e, key) != 0) {
			*found = 1;
			return e;
		}
		i = (i + 1U) & (cap - 1U);
	}
}


/* Tables keep a nonzero "used" first word in every element: count + 1 for pchist, etc. */


static int pcMatch(const void *e, const void *key)
{
	return ((const pchist_t *)e)->key == *(const uint64_t *)key;
}


/* tid + 1 in the top 16 bits (never 0: 0 marks a free slot), the PC in the low 48: user PCs are
 * below 2^39 and kernel ones 0xffffffffcxxxxxxx, so 48 bits keep them apart */
static uint64_t pcKey(int tid, uint64_t pc)
{
	return ((uint64_t)(((unsigned int)tid + 1U) & 0xffffU) << 48) | (pc & 0xffffffffffffULL);
}


static int pcTid(uint64_t key)
{
	return (int)(key >> 48) - 1;
}


static void pcAdd(int tid, uint64_t pc)
{
	uint64_t key = pcKey(tid, pc);
	pchist_t *e, *old, *n;
	size_t i, cap;
	int found;

	if (2U * (rep.npcs + 1U) > rep.cappcs) {
		cap = (rep.cappcs == 0U) ? 4096U : rep.cappcs * 2U;
		n = calloc(cap, sizeof(*n));
		if (n == NULL) {
			return;
		}
		old = rep.pcs;
		for (i = 0; i < rep.cappcs; i++) {
			if (old[i].key != 0U) {
				e = tableFind(n, cap, sizeof(*n), hash64(old[i].key), pcMatch, &old[i].key, &found);
				*e = old[i];
			}
		}
		free(old);
		rep.pcs = n;
		rep.cappcs = cap;
	}

	e = tableFind(rep.pcs, rep.cappcs, sizeof(*e), hash64(key), pcMatch, &key, &found);
	if (found == 0) {
		e->key = key;
		e->count = 0;
		rep.npcs++;
	}
	e->count++;
}


/* Linear tables (few entries): waits, edges, messages in flight */


static waitagg_t *waitAgg(int tid, int syscall, uint64_t obj)
{
	waitagg_t *w;
	size_t i;

	for (i = 0; i < rep.nwaits; i++) {
		w = &rep.waits[i];
		if ((w->tid == tid) && (w->syscall == syscall) && (w->obj == obj)) {
			return w;
		}
	}

	if (rep.nwaits == rep.capwaits) {
		rep.capwaits = (rep.capwaits == 0U) ? 256U : rep.capwaits * 2U;
		w = realloc(rep.waits, rep.capwaits * sizeof(*w));
		if (w == NULL) {
			return NULL;
		}
		rep.waits = w;
	}

	w = &rep.waits[rep.nwaits++];
	memset(w, 0, sizeof(*w));
	w->tid = tid;
	w->syscall = syscall;
	w->obj = obj;
	w->lastWaker = -1;

	return w;
}


static edge_t *edgeGet(int client, int server, uint32_t port)
{
	edge_t *e;
	size_t i;

	for (i = 0; i < rep.nedges; i++) {
		e = &rep.edges[i];
		if ((e->client == client) && (e->server == server) && (e->port == port)) {
			return e;
		}
	}

	if (rep.nedges == rep.capedges) {
		rep.capedges = (rep.capedges == 0U) ? 128U : rep.capedges * 2U;
		e = realloc(rep.edges, rep.capedges * sizeof(*e));
		if (e == NULL) {
			return NULL;
		}
		rep.edges = e;
	}

	e = &rep.edges[rep.nedges++];
	memset(e, 0, sizeof(*e));
	e->client = client;
	e->server = server;
	e->port = port;

	return e;
}


static inflight_t *msgFind(uint32_t mid, int create)
{
	inflight_t *m;
	size_t i;

	for (i = rep.nmsgs; i > 0U; i--) {
		if (rep.msgs[i - 1U].mid == mid) {
			return &rep.msgs[i - 1U];
		}
	}

	if (create == 0) {
		return NULL;
	}

	if (rep.nmsgs == rep.capmsgs) {
		rep.capmsgs = (rep.capmsgs == 0U) ? 64U : rep.capmsgs * 2U;
		m = realloc(rep.msgs, rep.capmsgs * sizeof(*m));
		if (m == NULL) {
			return NULL;
		}
		rep.msgs = m;
	}

	m = &rep.msgs[rep.nmsgs++];
	m->mid = mid;
	m->client = -1;
	m->server = -1;
	m->port = 0;

	return m;
}


static void msgDrop(inflight_t *m)
{
	*m = rep.msgs[--rep.nmsgs];
}


/* What a wait is on, by the syscall it happens in */
static uint64_t waitObject(int syscall, uint32_t queue, const uint64_t *args, const thr_t *t)
{
	const char *name = ((syscall >= 0) && (syscall < NSYSCALLS)) ? syscallNames[syscall] : "";

	/* a 32-bit argument leaves the upper half of its register unspecified (AAPCS64) */
	if (strcmp(name, "msgSend") == 0) {
		return (t->msgMid != 0U) ? t->msgPort : (uint32_t)args[0];
	}
	if (strcmp(name, "futexWait") == 0) {
		return args[0];
	}
	if ((strcmp(name, "msgRecv") == 0) || (strcmp(name, "phMutexLock") == 0) || (strcmp(name, "phCondWait") == 0) ||
		(strcmp(name, "threadJoin") == 0) || (strcmp(name, "sys_waitpid") == 0)) {
		return (uint32_t)args[0];
	}
	if (strcmp(name, "nsleep") == 0) {
		return 0;
	}

	return queue;
}


static void describeWait(char *buf, size_t sz, int syscall, uint64_t obj)
{
	const char *name = ((syscall >= 0) && (syscall < NSYSCALLS)) ? syscallNames[syscall] : NULL;

	if (name == NULL) {
		snprintf(buf, sz, "kernel queue 0x%08llx", (unsigned long long)obj);
	}
	else if ((strcmp(name, "msgSend") == 0) || (strcmp(name, "msgRecv") == 0)) {
		snprintf(buf, sz, "%s port %llu", name, (unsigned long long)obj);
	}
	else if (strcmp(name, "nsleep") == 0) {
		snprintf(buf, sz, "nsleep");
	}
	else if ((strcmp(name, "phMutexLock") == 0) || (strcmp(name, "phCondWait") == 0)) {
		snprintf(buf, sz, "%s handle %llu", name, (unsigned long long)obj);
	}
	else {
		snprintf(buf, sz, "%s 0x%llx", name, (unsigned long long)obj);
	}
}


static void longestAdd(const longwait_t *l)
{
	size_t i = rep.nlongest;

	if ((i == NLONGEST) && (rep.longest[NLONGEST - 1U].us >= l->us)) {
		return;
	}
	if (i < NLONGEST) {
		rep.nlongest++;
	}
	else {
		i = NLONGEST - 1U;
	}
	while ((i > 0U) && (rep.longest[i - 1U].us < l->us)) {
		rep.longest[i] = rep.longest[i - 1U];
		i--;
	}
	rep.longest[i] = *l;
}


/* A wait of t ended at ts (open: still waiting when the trace ended) */
static void waitEnd(int tid, thr_t *t, uint32_t ts, int open)
{
	uint32_t us = ts - t->waitTs;
	int cause = (open != 0) ? (int)CAUSES - 1 : ((t->wakeCause >= 0) ? t->wakeCause : (int)CAUSES - 1);
	waitagg_t *w;
	inflight_t *m;
	edge_t *e;
	longwait_t l;
	int server;

	w = waitAgg(tid, t->waitSyscall, t->waitObj);
	if (w != NULL) {
		w->count++;
		w->totalUs += us;
		if (us > w->maxUs) {
			w->maxUs = us;
		}
		if (open == 0) {
			w->causes[cause]++;
			if (t->waker > 0) {
				w->lastWaker = t->waker;
			}
		}
	}

	if (t->waitMid != 0U) {
		m = msgFind(t->waitMid, 0);
		server = ((m != NULL) && (m->server > 0)) ? m->server : t->waker;
		e = edgeGet(tid, server, (uint32_t)t->waitObj);
		if (e != NULL) {
			e->count++;
			e->totalUs += us;
			if (us > e->maxUs) {
				e->maxUs = us;
			}
		}
		if ((m != NULL) && (open == 0)) {
			msgDrop(m);
		}
	}

	l.tid = tid;
	l.syscall = t->waitSyscall;
	l.obj = t->waitObj;
	l.startTs = t->waitTs;
	l.us = us;
	l.timeout = t->waitTimeout;
	l.cause = cause;
	l.waker = (open == 0) ? t->waker : -1;
	l.existing = ((t->waitFlags & 1U) != 0U) ? 1 : 0;
	l.open = open;
	l.pc = t->waitPc;
	longestAdd(&l);

	t->waiting = 0;
	t->wakeCause = -1;
	t->waker = -1;
}


static void process(const ev_t *ev)
{
	const uint8_t *p = ev->p;
	thr_t *t;
	inflight_t *m;
	urec_t u;
	uint64_t args[4];
	size_t o;
	int tid, i;

	rep.lastTs = ev->ts;

	switch (ev->id) {
		case prof_ev_threadCreate:
		case prof_ev_processExec:
			t = thrGet(rd16(p + 2));
			if (t != NULL) {
				thrSetName(t, rd16(p), (const char *)p + 5, 128);
			}
			break;

		case prof_ev_syscallEnter:
			t = thrGet(rd16(p + 1));
			if (t != NULL) {
				t->syscall = p[0];
				t->msgMid = 0;
			}
			break;

		case prof_ev_syscallExit:
			t = thrGet(rd16(p + 1));
			if (t != NULL) {
				t->syscall = NO_SYSCALL;
				t->msgMid = 0;
			}
			break;

		case prof_ev_sample:
			tid = rd16(p);
			t = thrGet(tid);
			if ((t == NULL) || (p[2] > 2U)) {
				break;
			}
			t->samples[p[2]]++;
			rep.nsamples[p[2]]++;
			o = 12U + (size_t)p[11] * 8U;
			urecParse(p, o, &u);
			pcAdd(tid, (p[2] == 0U) ? u.pc : rd64(p + 3));
			break;

		case prof_ev_wait:
			tid = rd16(p);
			t = thrGet(tid);
			if (t == NULL) {
				break;
			}
			rep.nwaitEvents++;
			if (t->waiting != 0) {
				/* the previous wait ended without a waking event (should not happen) */
				waitEnd(tid, t, ev->ts, 1);
			}
			for (i = 0; i < 4; i++) {
				args[i] = rd64(p + 15 + 8 * i);
			}
			urecParse(p, 48U + (size_t)p[47] * 8U, &u);
			t->waiting = 1;
			t->waitFlags = p[2];
			/* deferred (bit 1): written when it ended, blocked = how long; else when it began */
			t->waitTs = ((p[2] & 2U) != 0U) ? ev->ts - rd32(p + 11) : ev->ts;
			t->waitSyscall = ((p[2] & 1U) != 0U) ? NO_SYSCALL : t->syscall;
			t->waitObj = waitObject(t->waitSyscall, rd32(p + 3), args, t);
			t->waitTimeout = rd32(p + 7);
			t->waitMid = t->msgMid;
			t->waitPc = (u.nframes > 0U) ? rd64(u.frames) : u.lr;
			if ((p[2] & 2U) == 0U) {
				/* a deferred wait's thread_wakeup came before it: keep that one */
				t->wakeCause = -1;
				t->waker = -1;
			}
			if ((p[2] & 4U) != 0U) {
				/* still waiting when the trace stopped */
				waitEnd(tid, t, ev->ts, 1);
			}
			break;

		case prof_ev_wakeup:
			t = thrGet(rd16(p));
			if (t != NULL) {
				t->waker = rd16(p + 2);
				t->wakeCause = (p[4] < CAUSES - 1U) ? p[4] : (int)CAUSES - 1;
			}
			break;

		case prof_ev_waking:
			tid = rd16(p);
			t = thrGet(tid);
			if ((t != NULL) && (t->waiting != 0)) {
				waitEnd(tid, t, ev->ts, 0);
			}
			else if (t != NULL) {
				/* a wakeup that ended no recorded wait must not stick to the next one */
				t->wakeCause = -1;
				t->waker = -1;
			}
			break;

		case prof_ev_msgSend:
			t = thrGet(rd16(p));
			m = msgFind(rd32(p + 10), 1);
			if ((t != NULL) && (m != NULL)) {
				t->msgMid = rd32(p + 10);
				t->msgPort = rd32(p + 2);
				t->msgType = rd32(p + 6);
				m->client = rd16(p);
				m->port = rd32(p + 2);
				m->server = -1;
			}
			break;

		case prof_ev_msgRecv:
			m = msgFind(rd32(p + 6), 0);
			if (m != NULL) {
				m->server = rd16(p);
			}
			break;

		case prof_ev_msgRespond:
			m = msgFind(rd32(p + 6), 0);
			if (m != NULL) {
				m->server = rd16(p);
				t = thrGet(m->client);
				/* the client's wait ends with the wakeup that follows; keep m until then */
				if ((t == NULL) || (t->waiting == 0) || (t->waitMid != m->mid)) {
					msgDrop(m);
				}
			}
			break;

		default:
			break;
	}
}


/* Output */


static int cmpDesc64(uint64_t a, uint64_t b)
{
	return (a > b) ? -1 : ((a < b) ? 1 : 0);
}


static int pcCmp(const void *a, const void *b)
{
	const pchist_t *x = a, *y = b;
	int tx = pcTid(x->key), ty = pcTid(y->key);

	if (tx != ty) {
		return (tx < ty) ? -1 : 1;
	}
	return cmpDesc64(x->count, y->count);
}


static int waitCmp(const void *a, const void *b)
{
	return cmpDesc64(((const waitagg_t *)a)->totalUs, ((const waitagg_t *)b)->totalUs);
}


static int edgeCmp(const void *a, const void *b)
{
	return cmpDesc64(((const edge_t *)a)->totalUs, ((const edge_t *)b)->totalUs);
}


static uint64_t pcValue(uint64_t key)
{
	uint64_t pc = key & 0xffffffffffffULL;

	return ((pc >> 47) != 0U) ? (pc | 0xffff000000000000ULL) : pc;
}


/* What the trace consists of: what to cut when it is too big */
static void printMix(void)
{
	static const char *const names[256] = {
		[prof_ev_irqEnter] = "interrupt_enter", [prof_ev_irqExit] = "interrupt_exit", [prof_ev_scheduling] = "thread_scheduling",
		[prof_ev_preempted] = "thread_preempted", [prof_ev_enqueued] = "thread_enqueued", [prof_ev_waking] = "thread_waking",
		[prof_ev_threadCreate] = "thread_create", [prof_ev_threadEnd] = "thread_end", [prof_ev_syscallEnter] = "syscall_enter",
		[prof_ev_syscallExit] = "syscall_exit", [prof_ev_schedEnter] = "sched_enter", [prof_ev_schedExit] = "sched_exit",
		[prof_ev_lockName] = "lock_name", [prof_ev_lockSetEnter] = "lock_set_enter", [prof_ev_lockSetAcquired] = "lock_set_acquired",
		[prof_ev_lockSetExit] = "lock_set_exit", [prof_ev_lockClear] = "lock_clear", [prof_ev_threadPriority] = "thread_priority",
		[prof_ev_processKill] = "process_kill", [prof_ev_processExec] = "process_exec", [prof_ev_sample] = "thread_sample",
		[prof_ev_wait] = "thread_wait", [prof_ev_wakeup] = "thread_wakeup", [prof_ev_msgSend] = "msg_send",
		[prof_ev_msgRecv] = "msg_recv", [prof_ev_msgRespond] = "msg_respond"
	};
	uint64_t total = 0, best;
	unsigned int i, k, pick;
	int shown[256] = { 0 };

	for (i = 0; i < 256U; i++) {
		total += rep.evBytes[i];
	}
	printf("\nEvent mix (%.1f MB; %.2f MB/s)\n", (double)total / 1048576.0,
		(rep.lastTs != 0U) ? (double)total / 1048576.0 / ((double)rep.lastTs / 1e6) : 0.0);
	for (k = 0; k < 256U; k++) {
		for (i = 0, best = 0, pick = 256U; i < 256U; i++) {
			if ((shown[i] == 0) && (rep.evBytes[i] > best)) {
				best = rep.evBytes[i];
				pick = i;
			}
		}
		if (pick == 256U) {
			break;
		}
		shown[pick] = 1;
		printf("  %-18s %10llu events %8.2f MB %5.1f%%\n", (names[pick] != NULL) ? names[pick] : "?",
			(unsigned long long)rep.evCount[pick], (double)rep.evBytes[pick] / 1048576.0, 100.0 * (double)rep.evBytes[pick] / (double)total);
	}
}


typedef struct {
	int pid;
	uint64_t user, kernel;
	char name[NAME_LEN];
} procagg_t;


static int procCmp(const void *a, const void *b)
{
	const procagg_t *x = a, *y = b;

	return cmpDesc64(x->user + x->kernel, y->user + y->kernel);
}


static void printCpu(void)
{
	procagg_t *procs = calloc(NPROCS, sizeof(*procs));
	uint64_t total = rep.nsamples[0] + rep.nsamples[1] + rep.nsamples[2];
	size_t nprocs = 0, i, j;
	thr_t *t;

	if ((procs == NULL) || (total == 0U)) {
		printf("\nno thread_sample events: was the trace recorded with sampling (prof record)?\n");
		free(procs);
		return;
	}

	for (i = 0; i < NTIDS; i++) {
		t = rep.thr[i];
		if ((t == NULL) || ((t->samples[0] + t->samples[1] + t->samples[2]) == 0U)) {
			continue;
		}
		for (j = 0; j < nprocs; j++) {
			if (procs[j].pid == t->pid) {
				break;
			}
		}
		if (j == nprocs) {
			if (nprocs == NPROCS) {
				continue;
			}
			procs[nprocs].pid = t->pid;
			snprintf(procs[nprocs].name, sizeof(procs[nprocs].name), "%.36s%s", (t->pid == 0) ? "[kernel threads + idle]" : t->name,
				((rep.selfPid > 0) && (t->pid == rep.selfPid)) ? " (recorder)" : "");
			nprocs++;
		}
		procs[j].user += t->samples[0];
		procs[j].kernel += t->samples[1] + t->samples[2];
	}

	qsort(procs, nprocs, sizeof(*procs), procCmp);

	printf("\nCPU by process (%% of all CPU time; %llu samples on %d CPUs)\n", (unsigned long long)total, rep.ncpus);
	printf("  %6s %-28s %8s %7s %7s\n", "pid", "process", "samples", "user%", "kern%");
	for (i = 0; i < nprocs; i++) {
		printf("  %6d %-28.28s %8llu %6.1f%% %6.1f%%\n", procs[i].pid, procs[i].name,
			(unsigned long long)(procs[i].user + procs[i].kernel),
			100.0 * (double)procs[i].user / (double)total, 100.0 * (double)procs[i].kernel / (double)total);
	}

	free(procs);
}


typedef struct {
	int tid;
	uint32_t samples;
} thrrank_t;


static int thrRankCmp(const void *a, const void *b)
{
	return cmpDesc64(((const thrrank_t *)a)->samples, ((const thrrank_t *)b)->samples);
}


static void printPcs(void)
{
	thrrank_t *rank = calloc(NTIDS, sizeof(*rank));
	size_t nrank = 0, i, j, k, shown;
	pchist_t *pcs;
	thr_t *t;
	int tid;

	if (rank == NULL) {
		return;
	}

	for (i = 0; i < NTIDS; i++) {
		t = rep.thr[i];
		if ((t != NULL) && (t->pid > 0) && (t->samples[0] + t->samples[1] != 0U) && (thrSelected((int)i) != 0)) {
			rank[nrank].tid = (int)i;
			rank[nrank].samples = t->samples[0] + t->samples[1];
			nrank++;
		}
	}
	qsort(rank, nrank, sizeof(*rank), thrRankCmp);

	/* the PC table, grouped by thread, by count */
	pcs = malloc((rep.npcs + 1U) * sizeof(*pcs));
	if (pcs == NULL) {
		free(rank);
		return;
	}
	for (i = 0, j = 0; i < rep.cappcs; i++) {
		if (rep.pcs[i].key != 0U) {
			pcs[j++] = rep.pcs[i];
		}
	}
	qsort(pcs, j, sizeof(*pcs), pcCmp);

	printf("\nBusiest threads (process samples; top PCs, kernel ones are 0xffffffff...)\n");
	for (i = 0; (i < nrank) && (i < rep.top); i++) {
		tid = rank[i].tid;
		t = rep.thr[tid];
		printf("  tid %-5d pid %-5d %-24.24s %6u samples (user %u, kernel %u)\n", tid, t->pid, t->name,
			rank[i].samples, t->samples[0], t->samples[1]);
		for (k = 0, shown = 0; (k < j) && (shown < 5U); k++) {
			if (pcTid(pcs[k].key) == tid) {
				printf("      %6u  0x%llx\n", pcs[k].count, (unsigned long long)pcValue(pcs[k].key));
				shown++;
			}
		}
	}

	free(pcs);
	free(rank);
}


static void printWaits(void)
{
	char what[64];
	size_t i, shown = 0;
	waitagg_t *w;
	unsigned int c;

	qsort(rep.waits, rep.nwaits, sizeof(*rep.waits), waitCmp);

	printf("\nWaits by total blocked time (per thread and object)\n");
	printf("  %5s %-20s %-30s %7s %10s %9s  %s\n", "tid", "process", "waiting in", "count", "total ms", "max ms", "ended by");
	for (i = 0; (i < rep.nwaits) && (shown < 4U * rep.top); i++) {
		w = &rep.waits[i];
		if (thrSelected(w->tid) == 0) {
			continue;
		}
		describeWait(what, sizeof(what), w->syscall, w->obj);
		printf("  %5d %-20.20s %-30.30s %7u %10.1f %9.1f ", w->tid, thrName(w->tid), what, w->count,
			(double)w->totalUs / 1000.0, (double)w->maxUs / 1000.0);
		for (c = 0; c < CAUSES; c++) {
			if (w->causes[c] != 0U) {
				printf(" %s:%u", causeNames[c], w->causes[c]);
			}
		}
		if (w->lastWaker > 0) {
			printf(" (last by %d %s)", w->lastWaker, thrName(w->lastWaker));
		}
		printf("\n");
		shown++;
	}
}


static void printLongest(void)
{
	char what[64];
	size_t i, shown = 0;
	longwait_t *l;

	printf("\nLongest single waits\n");
	for (i = 0; (i < rep.nlongest) && (shown < rep.top); i++) {
		l = &rep.longest[i];
		if (thrSelected(l->tid) == 0) {
			continue;
		}
		describeWait(what, sizeof(what), l->syscall, l->obj);
		printf("  %9.1f ms  tid %d %s at %.3f s%s: %s", (double)l->us / 1000.0, l->tid, thrName(l->tid),
			(double)l->startTs / 1e6, (l->existing != 0) ? " (or before: waiting at trace start)" : "", what);
		if (l->timeout != 0U) {
			printf(", timeout %.1f ms", (double)l->timeout / 1000.0);
		}
		if (l->open != 0) {
			printf(" -> still waiting at the end");
		}
		else {
			printf(" -> %s", causeNames[l->cause]);
			if (l->waker > 0) {
				printf(" by tid %d %s", l->waker, thrName(l->waker));
			}
		}
		printf("  [caller 0x%llx]\n", (unsigned long long)l->pc);
		shown++;
	}
}


static void printEdges(void)
{
	size_t i, shown = 0;
	edge_t *e;

	qsort(rep.edges, rep.nedges, sizeof(*rep.edges), edgeCmp);

	printf("\nWho blocked whom: msgSend client -> serving thread (by total wait)\n");
	for (i = 0; (i < rep.nedges) && (shown < 2U * rep.top); i++) {
		e = &rep.edges[i];
		if ((thrSelected(e->client) == 0) && (thrSelected(e->server) == 0)) {
			continue;
		}
		printf("  %5d %-18.18s -> port %-6u -> %5d %-18.18s %6u msgs %10.1f ms total %9.1f ms max\n", e->client,
			thrName(e->client), e->port, e->server, thrName(e->server), e->count, (double)e->totalUs / 1000.0,
			(double)e->maxUs / 1000.0);
		shown++;
	}
}


/* Process names of the threads from the start-time snapshot, before the trace's own */
static void loadInfo(const char *dir)
{
	char path[PATH_MAX], line[256], name[160];
	unsigned int tid;
	int pid, ppid;
	FILE *f;
	thr_t *t;

	snprintf(path, sizeof(path), "%s/%s", dir, PROF_INFO_FILE);
	f = fopen(path, "r");
	if (f == NULL) {
		return;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		if (((sscanf(line, "thread %u %d %d %159[^\n]", &tid, &pid, &ppid, name) == 4) ||
				(sscanf(line, "thread-end %u %d %d %159[^\n]", &tid, &pid, &ppid, name) == 4)) &&
			((t = thrGet((int)tid)) != NULL) && (t->pid < 0)) {
			thrSetName(t, pid, name, strlen(name));
		}
		else if ((rep.pidFilter == 0) && (sscanf(line, "pid %d", &pid) == 1)) {
			rep.pidFilter = pid;
		}
		else if (sscanf(line, "self %d", &pid) == 1) {
			rep.selfPid = pid;
		}
	}

	fclose(f);
}


int prof_report(int argc, char **argv)
{
	const char *dir = PROF_DEFAULT_DIR;
	char path[PATH_MAX];
	thr_t *t;
	size_t i;
	int opt, cpu, kind, loaded;

	memset(&rep, 0, sizeof(rep));
	rep.top = 10;

	optind = 1;
	while ((opt = getopt(argc, argv, "p:n:")) != -1) {
		switch (opt) {
			case 'p':
				rep.pidFilter = (int)strtol(optarg, NULL, 0);
				break;
			case 'n':
				rep.top = (unsigned int)strtoul(optarg, NULL, 0);
				break;
			default:
				fprintf(stderr, "prof: bad option, see `prof`\n");
				return 1;
		}
	}
	if (optind < argc) {
		dir = argv[optind];
	}

	loadInfo(dir);

	for (cpu = 0;; cpu++) {
		loaded = 0;
		for (kind = 0; kind < 2; kind++) {
			snprintf(path, sizeof(path), "%s/%s%d", dir, (kind == 0) ? "channel_meta" : "channel_event", cpu);
			if (loadStream(path, cpu) == 0) {
				loaded++;
			}
		}
		if (loaded == 0) {
			break;
		}
	}
	rep.ncpus = cpu;

	if (rep.nevs == 0U) {
		fprintf(stderr, "prof: no trace in %s\n", dir);
		return 1;
	}

	qsort(rep.evs, rep.nevs, sizeof(*rep.evs), evCmp);
	for (i = 0; i < rep.nevs; i++) {
		process(&rep.evs[i]);
	}

	/* waits still open at the end of the trace */
	for (i = 0; i < NTIDS; i++) {
		t = rep.thr[i];
		if ((t != NULL) && (t->waiting != 0)) {
			waitEnd((int)i, t, rep.lastTs, 1);
		}
	}

	printf("prof: %s: %.2f s, %d CPUs, %zu events, %llu samples, %llu waits\n", dir, (double)rep.lastTs / 1e6, rep.ncpus,
		rep.nevs, (unsigned long long)(rep.nsamples[0] + rep.nsamples[1] + rep.nsamples[2]),
		(unsigned long long)rep.nwaitEvents);
	if (rep.pidFilter > 0) {
		printf("prof: threads of pid %d only (CPU table: all)\n", rep.pidFilter);
	}

	printMix();
	printCpu();
	printPcs();
	printLongest();
	printWaits();
	printEdges();

	for (i = 0; i < rep.nfiles; i++) {
		free(rep.files[i]);
	}
	for (i = 0; i < NTIDS; i++) {
		free(rep.thr[i]);
	}
	free(rep.files);
	free(rep.evs);
	free(rep.pcs);
	free(rep.waits);
	free(rep.edges);
	free(rep.msgs);

	return 0;
}
