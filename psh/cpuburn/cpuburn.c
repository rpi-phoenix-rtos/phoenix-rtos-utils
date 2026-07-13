/*
 * Phoenix-RTOS
 *
 * cpuburn - diagnostic CPU-load generator
 *
 * Spawns N worker threads, each running a tight compute loop, to saturate
 * multiple cores so that per-core scheduling / utilization (e.g. `top`'s
 * per-core summary) can be observed on SMP targets. Diagnostic use only.
 *
 * The workers run in the BACKGROUND: cpuburn returns to the shell immediately
 * after spawning, and a detached controller thread stops + reaps them after the
 * -t deadline. That way you can start a load and then run `top` in the same psh
 * to watch it distribute across cores (psh has no job control / `&`).
 *
 * Copyright 2026 Phoenix Systems
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/threads.h>

#include "../psh.h"


#define CPUBURN_MAX_THREADS 64
#define CPUBURN_STACKSZ     (4 * 4096) /* 16 KiB per worker */
#define CPUBURN_CTRL_STACKSZ (4 * 4096)

/* Lowest usable priority level. The kernel reserves the last ready[] level
 * (MAX_PRIO) for the per-CPU idle thread, so the coarsest a worker may run at
 * is one above that. Phoenix has 8 priority levels (0..7). */
#define CPUBURN_MIN_PRIORITY 6


struct cpuburn_ctx;

/* Per-worker argument (ctx + slot id). Stored inside the context (below) so it
 * outlives the returning cpuburn command and is freed together with the context. */
typedef struct {
	struct cpuburn_ctx *ctx;
	unsigned int id;
} cpuburn_arg_t;


/* Per-invocation state (heap) so multiple concurrent cpuburn runs don't clash and
 * the workers/controller outlive the returning cpuburn command. */
typedef struct cpuburn_ctx {
	volatile int stop;
	long secs;
	int spawned;
	void *stacks[CPUBURN_MAX_THREADS];
	handle_t tids[CPUBURN_MAX_THREADS];
	void *ctrlStack;
	volatile unsigned long long tick[CPUBURN_MAX_THREADS];
	cpuburn_arg_t wargs[CPUBURN_MAX_THREADS];
} cpuburn_ctx_t;


/* Tight compute loop; touches integer + FP so the core cannot idle. */
static void cpuburn_worker(void *arg)
{
	cpuburn_arg_t *wa = (cpuburn_arg_t *)arg;
	cpuburn_ctx_t *ctx = wa->ctx;
	unsigned int id = wa->id;
	volatile double acc = 1.0;
	unsigned long long n = 0;

	while (ctx->stop == 0) {
		unsigned int i;
		for (i = 0; i < 100000u; i++) {
			acc = acc * 1.000001 + 1.0;
			if (acc > 1.0e6) {
				acc = 1.0;
			}
		}
		n++;
		ctx->tick[id] = n;
	}

	endthread();
}


/* Detached controller: enforce the -t deadline, then stop + reap the workers,
 * free every allocation (including the context + its own stack), and exit. Runs
 * at the caller's priority so it always preempts the (lower-prio) workers. */
static void cpuburn_controller(void *arg)
{
	cpuburn_ctx_t *ctx = (cpuburn_ctx_t *)arg;
	struct timespec ts;
	time_t start, now;
	int i;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	start = ts.tv_sec;
	for (;;) {
		if (ctx->secs > 0) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			now = ts.tv_sec;
			if ((now - start) >= ctx->secs) {
				break;
			}
		}
		if (ctx->stop != 0) {
			break;
		}
		usleep(100000);
	}

	ctx->stop = 1;
	for (i = 0; i < ctx->spawned; i++) {
		(void)threadJoin(ctx->tids[i], 0);
		free(ctx->stacks[i]);
	}
	/* NOTE: we must NOT free ctx->ctrlStack here — this controller thread is
	 * running ON that stack, and a 16 KiB malloc is mmap-backed, so free()ing it
	 * would munmap the live stack and fault on the next stack access (observed as
	 * a Data Abort at munmap's epilogue, far=sp). The controller stack is a small,
	 * bounded, one-per-cpuburn-run leak — acceptable for a diagnostic tool; a
	 * self-freeing thread stack would need endthread() to release it post-switch.
	 * ctx itself is heap (not the running stack), so freeing it is safe. */
	free(ctx);
	endthread();
}


static void psh_cpuburninfo(void)
{
	printf("saturates N cpus with background busy threads (diagnostic)");
}


static void psh_cpuburn_help(const char *progname)
{
	printf("Usage: %s [N] [-t secs] [-h]\n", progname);
	printf("  N        number of burn threads to spawn (default 4, max %d)\n", CPUBURN_MAX_THREADS);
	printf("  -t secs  auto-stop after this many seconds (default 20; 0 = until reboot)\n");
	printf("  -h       show this help\n");
	printf("Spawns the load in the BACKGROUND and returns; run `top` to watch it\n");
	printf("distribute across cores (per-core summary line).\n");
}


static int psh_cpuburn(int argc, char **argv)
{
	int c, i;
	long nthreads = 4;
	long secs = 20;
	char *end;
	int workerPrio, ctrlPrio;
	cpuburn_ctx_t *ctx;
	handle_t ctrlTid;

	while ((c = getopt(argc, argv, "t:h")) != -1) {
		switch (c) {
			case 't':
				secs = strtol(optarg, &end, 10);
				if (*end != '\0' || secs < 0) {
					fprintf(stderr, "cpuburn: -t requires a non-negative integer\n");
					return -EINVAL;
				}
				break;

			case 'h':
			default:
				psh_cpuburn_help(argv[0]);
				return EOK;
		}
	}

	if (optind < argc) {
		nthreads = strtol(argv[optind], &end, 10);
		if (*end != '\0' || nthreads <= 0) {
			fprintf(stderr, "cpuburn: thread count must be a positive integer\n");
			return -EINVAL;
		}
	}
	if (nthreads > CPUBURN_MAX_THREADS) {
		nthreads = CPUBURN_MAX_THREADS;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		fprintf(stderr, "cpuburn: out of memory\n");
		return -ENOMEM;
	}
	ctx->secs = secs;

	/* Workers one level BELOW the controller so the controller (and the shell +
	 * system daemons) always preempt them: the -t deadline and reboot stay
	 * responsive even with every core saturated. */
	ctrlPrio = priority(-1);
	workerPrio = ctrlPrio + 1;
	if (workerPrio > CPUBURN_MIN_PRIORITY) {
		workerPrio = CPUBURN_MIN_PRIORITY;
	}

	for (i = 0; i < nthreads; i++) {
		ctx->stacks[i] = malloc(CPUBURN_STACKSZ);
		ctx->wargs[i].ctx = ctx;
		ctx->wargs[i].id = (unsigned int)i;
		if (ctx->stacks[i] == NULL
				|| beginthreadex(cpuburn_worker, (unsigned int)workerPrio, ctx->stacks[i],
						CPUBURN_STACKSZ, &ctx->wargs[i], &ctx->tids[i]) < 0) {
			fprintf(stderr, "cpuburn: failed to start worker %d\n", i);
			free(ctx->stacks[i]);
			break;
		}
		ctx->spawned++;
	}

	if (ctx->spawned == 0) {
		free(ctx);
		fprintf(stderr, "cpuburn: no threads started\n");
		return -EAGAIN;
	}

	/* The workers hold &ctx->wargs[i], so the arguments live inside the context and
	 * are reclaimed together with it by the controller — no separate lifetime. */
	ctx->ctrlStack = malloc(CPUBURN_CTRL_STACKSZ);
	if (ctx->ctrlStack == NULL
			|| beginthreadex(cpuburn_controller, (unsigned int)ctrlPrio, ctx->ctrlStack,
					CPUBURN_CTRL_STACKSZ, ctx, &ctrlTid) < 0) {
		/* No controller: fall back to stopping now so we don't leak a runaway load. */
		free(ctx->ctrlStack);
		ctx->stop = 1;
		for (i = 0; i < ctx->spawned; i++) {
			(void)threadJoin(ctx->tids[i], 0);
			free(ctx->stacks[i]);
		}
		free(ctx);
		fprintf(stderr, "cpuburn: failed to start controller\n");
		return -EAGAIN;
	}

	printf("cpuburn: %d thread(s) burning in the background", ctx->spawned);
	if (secs > 0) {
		printf(" for %ld s", secs);
	}
	printf(" — run `top` to watch per-core load.\n");
	return EOK;
}


void __attribute__((constructor)) cpuburn_registerapp(void)
{
	static psh_appentry_t app = { .name = "cpuburn", .run = psh_cpuburn, .info = psh_cpuburninfo };
	psh_registerapp(&app);
}
