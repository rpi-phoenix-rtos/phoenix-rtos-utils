/*
 * Phoenix-RTOS — NFS client smoke test (T1 feasibility gate, #153)
 *
 * Proves the libnfs port works end-to-end over the real NIC: waits for a DHCP
 * lease, mounts an NFS export, reads a file, then writes a marker file back.
 * Arch-neutral — only the launcher line (and server IP) differ per platform.
 *
 * Usage (argv): nfs-smoke [server-ip] [export-path] [file-to-read]
 *   defaults:  10.42.0.1  /  /etc/hostname     (NFSv4, fsid=0 pseudo-root)
 *
 * Copyright 2026 Phoenix Systems
 *
 * %LICENSE%
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <nfsc/libnfs.h>

/* nfs_set_version() takes the NFS protocol program version as a plain int.
 * The NFS_V3/NFS_V4 macros are defined in libnfs's internal RPC headers
 * (nfs/libnfs-raw-nfs.h, nfs4/libnfs-raw-nfs4.h) which the port does not
 * install into the public <nfsc/> set, so define the stable wire values here. */
#ifndef NFS_V3
#define NFS_V3 3
#endif
#ifndef NFS_V4
#define NFS_V4 4
#endif

#define TAG "nfs-smoke"


static uint64_t now_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0;
	}
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}


static int valid_ipv4(const char *s)
{
	int parts = 0, digits = 0, val = 0, nonzero = 0;
	for (;; s++) {
		if (*s >= '0' && *s <= '9') {
			val = val * 10 + (*s - '0');
			digits++;
			if (val > 255) {
				return 0;
			}
		}
		else if (*s == '.' || *s == '\0') {
			if (digits == 0) {
				return 0;
			}
			if (val != 0) {
				nonzero = 1;
			}
			parts++;
			if (*s == '\0') {
				break;
			}
			val = 0;
			digits = 0;
		}
		else {
			return 0;
		}
	}
	return (parts == 4 && nonzero) ? 1 : 0;
}


/* Scan /dev/ifstatus for ANY non-lo/wl/sc interface that is up with a bound
 * IPv4. Interface-name-agnostic on purpose (Pi4 en0, ia32-qemu en1, ...). */
static int wait_for_dhcp_lease(char *ip_out, size_t cap, int timeout_ms)
{
	int waited = 0;
	for (;;) {
		FILE *f = fopen("/dev/ifstatus", "r");
		if (f != NULL) {
			char line[160];
			char cur_if[24] = "";
			int cur_up = 0;
			while (fgets(line, sizeof(line), f) != NULL) {
				char *us = strchr(line, '_');
				char *eq = strchr(line, '=');
				if (us == NULL || eq == NULL || us > eq) {
					continue;
				}
				/* ifname = text before first '_'; key = between '_' and '='. */
				size_t iflen = (size_t)(us - line);
				char ifname[24];
				if (iflen == 0 || iflen >= sizeof(ifname)) {
					continue;
				}
				memcpy(ifname, line, iflen);
				ifname[iflen] = '\0';

				char key[24];
				size_t keylen = (size_t)(eq - (us + 1));
				if (keylen == 0 || keylen >= sizeof(key)) {
					continue;
				}
				memcpy(key, us + 1, keylen);
				key[keylen] = '\0';

				char val[64];
				size_t vlen = strlen(eq + 1);
				while (vlen > 0 && (eq[vlen] == '\n' || eq[vlen] == '\r' || eq[vlen] == '\0')) {
					vlen--; /* trim trailing newline (eq+1+vlen) */
				}
				/* recompute cleanly */
				strncpy(val, eq + 1, sizeof(val) - 1);
				val[sizeof(val) - 1] = '\0';
				char *nl = strpbrk(val, "\r\n");
				if (nl != NULL) {
					*nl = '\0';
				}

				int is_lo = (strncmp(ifname, "lo", 2) == 0) || (strncmp(ifname, "wl", 2) == 0) || (strncmp(ifname, "sc", 2) == 0);
				if (is_lo) {
					continue;
				}

				if (strcmp(key, "up") == 0) {
					strncpy(cur_if, ifname, sizeof(cur_if) - 1);
					cur_if[sizeof(cur_if) - 1] = '\0';
					cur_up = (atoi(val) != 0);
				}
				else if (strcmp(key, "ip") == 0) {
					if (cur_up && strcmp(ifname, cur_if) == 0 && valid_ipv4(val)) {
						strncpy(ip_out, val, cap - 1);
						ip_out[cap - 1] = '\0';
						fclose(f);
						return 0;
					}
				}
			}
			fclose(f);
		}
		if (waited >= timeout_ms) {
			return -1;
		}
		usleep(250000);
		waited += 250;
	}
}


int main(int argc, char **argv)
{
	const char *srv = (argc > 1) ? argv[1] : "10.42.0.1";
	const char *exp = (argc > 2) ? argv[2] : "/";
	const char *file = (argc > 3) ? argv[3] : "/etc/hostname";
	char ipbuf[64] = "";

	printf("%s: start (server=%s export=%s file=%s)\n", TAG, srv, exp, file);

	if (wait_for_dhcp_lease(ipbuf, sizeof(ipbuf), 30000) != 0) {
		fprintf(stderr, "%s: FAIL no DHCP lease in 30s\n", TAG);
		return 2;
	}
	printf("%s: interface bound, ip=%s\n", TAG, ipbuf);

	struct nfs_context *nfs = nfs_init_context();
	if (nfs == NULL) {
		fprintf(stderr, "%s: FAIL nfs_init_context\n", TAG);
		return 3;
	}

	/* #156: stable, role-distinct NFSv4 client id (see srv.c nfs_makeContext).
	 * libnfs's default pid+time id changes every boot, so the server keeps this
	 * diagnostic's stale lease ~90 s after each run; a fixed id lets a reboot
	 * replace it, and the distinct role avoids colliding with the nfs-fs server's
	 * client on this same host. */
	nfs4_set_client_name(nfs, "phoenix-rpi4-nfssmoke");

	nfs_set_version(nfs, NFS_V4);
	nfs_set_timeout(nfs, 5000);
	nfs_set_poll_timeout(nfs, 1);        /* default 100ms; Phoenix poll() blocks the full timeout -> 100ms/RPC */
	nfs_set_readmax(nfs, 1024 * 1024);   /* match the fs server (srv.c) for a realistic throughput number */
	nfs_set_writemax(nfs, 1024 * 1024);

	uint64_t tm0 = now_ms();
	int mrc = nfs_mount(nfs, srv, exp);
	uint64_t tm1 = now_ms();
	if (mrc != 0) {
		fprintf(stderr, "%s: v4 mount failed (%llu ms): %s\n", TAG, (unsigned long long)(tm1 - tm0), nfs_get_error(nfs));
		/* Fallback: v3 over TCP. */
		nfs_destroy_context(nfs);
		nfs = nfs_init_context();
		if (nfs == NULL) {
			return 3;
		}
		nfs_set_version(nfs, NFS_V3);
		nfs_set_timeout(nfs, 5000);
		if (nfs_mount(nfs, srv, "/srv/phoenix-rpi4-nfs") != 0) {
			fprintf(stderr, "%s: FAIL v3 mount also failed: %s\n", TAG, nfs_get_error(nfs));
			nfs_destroy_context(nfs);
			return 4;
		}
		printf("%s: mounted via NFSv3 fallback\n", TAG);
	}
	else {
		printf("%s: mounted %s:%s via NFSv4 in %llu ms\n", TAG, srv, exp, (unsigned long long)(tm1 - tm0));
	}

	struct nfsfh *fh = NULL;
	if (nfs_open(nfs, file, O_RDONLY, &fh) != 0) {
		fprintf(stderr, "%s: FAIL open %s: %s\n", TAG, file, nfs_get_error(nfs));
		nfs_destroy_context(nfs);
		return 6;
	}
	char buf[513];
	uint64_t tr0 = now_ms();
	int n = nfs_pread(nfs, fh, buf, sizeof(buf) - 1, 0);
	uint64_t tr1 = now_ms();
	nfs_close(nfs, fh);
	if (n < 0) {
		fprintf(stderr, "%s: FAIL pread %s: %s\n", TAG, file, nfs_get_error(nfs));
		nfs_destroy_context(nfs);
		return 7;
	}
	buf[n] = '\0';
	printf("%s: READ ok %d bytes in %llu ms: \"%s\"\n", TAG, n, (unsigned long long)(tr1 - tr0), buf);

	/* Write half: create a marker, write, read back, compare. */
	struct nfsfh *wfh = NULL;
	const char *marker = "phoenix-nfs-smoke-OK\n";
	/* The marker persists on the export from a prior boot, so a plain creat fails
	 * with NFS4ERR_EXIST. Remove it first (ignore errors) so each run starts clean. */
	(void)nfs_unlink(nfs, "/nfs-smoke-marker.txt");
	if (nfs_creat(nfs, "/nfs-smoke-marker.txt", 0644, &wfh) == 0) {
		int wn = nfs_pwrite(nfs, wfh, (void *)marker, strlen(marker), 0);
		nfs_close(nfs, wfh);
		if (wn == (int)strlen(marker)) {
			char rb[64] = "";
			struct nfsfh *vfh = NULL;
			if (nfs_open(nfs, "/nfs-smoke-marker.txt", O_RDONLY, &vfh) == 0) {
				int rn = nfs_pread(nfs, vfh, rb, sizeof(rb) - 1, 0);
				nfs_close(nfs, vfh);
				if (rn > 0) {
					rb[rn] = '\0';
				}
				if (rn == wn && memcmp(rb, marker, wn) == 0) {
					printf("%s: WRITE ok (%d bytes, readback MATCH)\n", TAG, wn);
				}
				else {
					printf("%s: WRITE readback MISMATCH (wrote %d, read %d)\n", TAG, wn, rn);
				}
			}
		}
		else {
			fprintf(stderr, "%s: pwrite short (%d/%d): %s\n", TAG, wn, (int)strlen(marker), nfs_get_error(nfs));
		}
	}
	else {
		fprintf(stderr, "%s: creat marker failed: %s\n", TAG, nfs_get_error(nfs));
	}

	/* --- FS HEALTH micro-benchmark (boot-time): RPC round-trip latency + read throughput.
	 * Prints one line per boot so a glance shows whether the FS is performing normally or
	 * DEGRADED (stale NFSv4 server state, v4 grace period, link trouble). Latency is the key
	 * regression detector on this latency-bound link; throughput needs a sizable file. */
	{
		struct nfs_stat_64 st;
		int i, statok = 1;
		const int N = 50;
		uint64_t b0 = now_ms();
		for (i = 0; i < N; i++) {
			if (nfs_lstat64(nfs, file, &st) != 0) {
				statok = 0;
				break;
			}
		}
		uint64_t b1 = now_ms();
		double us_per_rpc = statok ? ((double)(b1 - b0) * 1000.0 / (double)N) : -1.0;

		double mbps = -1.0;
		long total = 0;
		static const char *bigcands[] = { "/usr/share/quake/id1/pak0.pak", "/id1/pak0.pak", NULL };
		int ci;
		for (ci = 0; bigcands[ci] != NULL; ci++) {
			struct nfsfh *bf = NULL;
			if (nfs_open(nfs, bigcands[ci], O_RDONLY, &bf) == 0) {
				static char rbuf[256 * 1024];
				long targ = 2 * 1024 * 1024;
				uint64_t r0 = now_ms();
				while (total < targ) {
					int rn = nfs_pread(nfs, bf, rbuf, sizeof(rbuf), (uint64_t)total);
					if (rn <= 0) {
						break;
					}
					total += rn;
				}
				uint64_t r1 = now_ms();
				nfs_close(nfs, bf);
				if (total > 0 && r1 > r0) {
					mbps = ((double)total / 1e6) / ((double)(r1 - r0) / 1000.0);
				}
				break;
			}
		}

		/* thresholds (tunable): a healthy RPC round-trip on this link is a few ms; >20 ms/op
		 * or <1.5 MB/s (when a big file exists) flags a degraded FS. */
		int healthy = (us_per_rpc >= 0.0 && us_per_rpc < 20000.0) && (mbps < 0.0 || mbps > 1.5);
		if (mbps >= 0.0) {
			printf("%s: FSHEALTH rpc=%.0f us/op  read=%.2f MB/s (%ld B)  -> %s\n",
			       TAG, us_per_rpc, mbps, total, healthy ? "HEALTHY" : "DEGRADED");
		}
		else {
			printf("%s: FSHEALTH rpc=%.0f us/op  read=n/a(no big file)  -> %s\n",
			       TAG, us_per_rpc, healthy ? "HEALTHY" : "DEGRADED");
		}
	}

	/* --- WRITE throughput micro-benchmark: 4 MB to a scratch file via direct libnfs
	 * nfs_pwrite (the working write path; the nfs-fs VFS write bridge is a separate
	 * known issue). Mirrors the read FSHEALTH so we track read AND write MB/s. --- */
	{
		struct nfsfh *wf = NULL;
		double wmbps = -1.0;
		long wtotal = 0;
		(void)nfs_unlink(nfs, "/nfs-smoke-wtest.dat");
		if (nfs_creat(nfs, "/nfs-smoke-wtest.dat", 0644, &wf) == 0) {
			static char wbuf[256 * 1024];
			long wtarg = 4 * 1024 * 1024;
			uint64_t w0, w1;
			memset(wbuf, 0xa5, sizeof(wbuf));
			w0 = now_ms();
			while (wtotal < wtarg) {
				int wn2 = nfs_pwrite(nfs, wf, wbuf, sizeof(wbuf), (uint64_t)wtotal);
				if (wn2 <= 0) {
					break;
				}
				wtotal += wn2;
			}
			w1 = now_ms();
			nfs_close(nfs, wf);
			if (wtotal > 0 && w1 > w0) {
				wmbps = ((double)wtotal / 1e6) / ((double)(w1 - w0) / 1000.0);
			}
			(void)nfs_unlink(nfs, "/nfs-smoke-wtest.dat");
		}
		if (wmbps >= 0.0) {
			printf("%s: WHEALTH write=%.2f MB/s (%ld B)\n", TAG, wmbps, wtotal);
		}
		else {
			printf("%s: WHEALTH write=n/a (creat/pwrite failed: %s)\n", TAG, nfs_get_error(nfs));
		}
	}

	nfs_destroy_context(nfs);
	printf("%s: DONE (overall PASS if READ ok + WRITE ok above)\n", TAG);
	return 0;
}
