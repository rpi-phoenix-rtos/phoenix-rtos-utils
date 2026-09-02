/*
 * Phoenix-RTOS
 *
 * ntpclient - set the system's date from a remote host
 *
 * Copyright 2022 Phoenix Systems
 * Author: Gerard Swiderski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>

#include "../psh.h"


#define NTP_JAN1970_DELTA 2208988800ull

/* Convert fraction (divide by 4294.967296) to uSec */
#define FRAC_TO_USEC(x) (((x) >> 12) - 759 * ((((x) >> 10) + 32768) >> 16))

#define NTP_LI_VN_MODE(li, vn, mode) (((((uint8_t)li) & 3) << 6) | ((((uint8_t)vn) & 7) << 3) | ((((uint8_t)mode) & 7) << 0))
#define NTP_VERSION(li_vn_mode)      ((uint8_t)(((li_vn_mode) >> 3) & 7))
#define NTP_LEAP(li_vn_mode)         ((uint8_t)(((li_vn_mode) >> 6) & 3))
#define NTP_LEAP_NOSYNC              0

#define NTP_MODE(li_vn_mode) ((uint8_t)(((li_vn_mode) >> 0) & 7))
#define NTP_MODE_PASSIVE     2
#define NTP_MODE_CLIENT      3
#define NTP_MODE_SERVER      4


struct sntp_pkt_s {
	uint8_t li_vn_mode;      /* Leap indicator, version, mode */
	uint8_t stratum;         /* Stratum level of the local clock. */
	uint8_t poll;            /* Maximum interval between successive messages. */
	int8_t precision;        /* Precision of the local clock. */
	uint32_t rootDelay;      /* Total round trip delay time. */
	uint32_t rootDispersion; /* Max error aloud from primary clock source. */
	uint32_t refId;          /* Reference clock identifier. */
	uint32_t refTm_sec;      /* Reference time-stamp seconds. */
	uint32_t refTm_frac;     /* Reference time-stamp fraction of a second. */
	uint32_t origTm_sec;     /* Originate time-stamp seconds. */
	uint32_t origTm_frac;    /* Originate time-stamp fraction of a second. */
	uint32_t rxTm_sec;       /* Received time-stamp seconds. */
	uint32_t rxTm_frac;      /* Received time-stamp fraction of a second. */
	uint32_t txTm_sec;       /* Transmit time-stamp seconds. */
	uint32_t txTm_frac;      /* Transmit time-stamp fraction of a second. */
} __attribute__((packed));


/* How long to sleep between attempts while -w is still counting down. */
#define NTP_RETRY_INTERVAL_S 3

/* Set for the whole of a -w window: an unreachable network would otherwise
 * print one getaddrinfo/socket error per attempt. The single "clock NOT set"
 * line at the end is the diagnosis the user needs; thirty syscall errors
 * scrolling past a fresh shell prompt are not. */
static int ntpclient_silent = 0;


static int doError(const char *fName, int err)
{
	if (ntpclient_silent != 0) {
		return err;
	}

	fprintf(stderr, "ntpclient: %s() failed, err=%d\n", fName, err);
	return err;
}


static uint32_t *aiToAddr(struct addrinfo *ai)
{
	return &(((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr);
}


/* Default seconds to wait for the server's reply. Without a bound, an
 * unreachable or silent server blocks read() forever, which makes ntpclient
 * unusable from a boot script: the Pi4 boot config runs it before psh, so a
 * hang there would cost the shell. */
#define NTP_RECV_TIMEOUT_S 5



static int ntpclient_connect(const char *host, unsigned int timeout)

{
	int ret = EOK, sockfd;
	struct addrinfo *res;
	/* AI_NUMERICSERV: the service is already the literal "123", and without
	 * this the resolver is entitled to look it up in /etc/services -- which on
	 * a netboot/NFS root is a network file access that the socket timeout below
	 * cannot bound. A boot that ran this from an rc script then hung before
	 * reaching the shell. */
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP, .ai_flags = AI_NUMERICSERV };
	char hostaddr[INET_ADDRSTRLEN];
	struct timeval tv;

	if (host == NULL) {
		return doError("ntpclient_connect", -EINVAL);
	}

	if (ntpclient_silent == 0) {
		printf("Using NTP server: %s\n", host);
	}

	ret = getaddrinfo(host, "123", &hints, &res);
	if (ret != 0) {
		if (ret == EAI_SYSTEM) {
			ret = -errno;
		}
		return doError("getaddrinfo", ret);
	}

	do {
		if (inet_ntop(res->ai_family, aiToAddr(res), hostaddr, sizeof(hostaddr)) == NULL) {
			ret = doError("inet_ntop", -errno);
			break;
		}

		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0) {
			ret = doError("socket", -errno);
			break;
		}

		/* Bound the wait for the reply. SO_RCVTIMEO makes read() fail with
		 * EAGAIN instead of blocking indefinitely; the read loop turns that
		 * into -ETIMEDOUT. */
		tv.tv_sec = (time_t)timeout;
		tv.tv_usec = 0;
		if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			ret = doError("setsockopt(SO_RCVTIMEO)", -errno);
			close(sockfd);
			break;
		}

		/* The send loop had the same unbounded EAGAIN retry as the receive
		 * loop, so a full socket buffer was its own busy-spin forever. */
		if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
			ret = doError("setsockopt(SO_SNDTIMEO)", -errno);
			close(sockfd);
			break;
		}

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
			ret = doError("connect", -errno);
			close(sockfd);
			break;
		}

		ret = sockfd;
	} while (0);

	freeaddrinfo(res);

	return ret;
}


static int ntpclient_gettimepacket(int sockfd, struct sntp_pkt_s *pkt)
{
	size_t len;
	uint8_t *ptr;

	memset(pkt, 0, sizeof(*pkt));

	pkt->li_vn_mode = NTP_LI_VN_MODE(NTP_LEAP_NOSYNC, 4, NTP_MODE_CLIENT);
	pkt->stratum = 16; /* use unspecified stratum, as we're out of sync */
	pkt->poll = 3;
	pkt->precision = -6;

	len = sizeof(*pkt);
	ptr = (uint8_t *)pkt;
	while (len > 0) {
		ssize_t bytes = write(sockfd, ptr, len);
		if (bytes < 0) {
			/* SO_SNDTIMEO makes EAGAIN mean the timeout expired; retrying it
			 * unconditionally (as this did) never terminates. */
			if (errno == EAGAIN) {
				return doError("write (send timed out)", -ETIMEDOUT);
			}
			if (errno != EINTR) {
				return doError("write", -errno);
			}
			continue;
		}
		len -= bytes;
		ptr += bytes;
	}

	/* One datagram, not a byte loop: this is SOCK_DGRAM, so a reply either
	 * arrives whole or not at all. Looping meant a short (or empty) packet was
	 * not an error -- it went back and waited another full timeout for the
	 * "rest" of a datagram that will never come. */
	for (;;) {
		ssize_t bytes = read(sockfd, pkt, sizeof(*pkt));
		if (bytes == (ssize_t)sizeof(*pkt)) {
			break;
		}
		if (bytes >= 0) {
			return doError("read (short reply)", -EPROTO);
		}
		/* With SO_RCVTIMEO set, EAGAIN is the timeout expiring -- retrying it
		 * (as this used to, unconditionally) is an endless busy loop against a
		 * silent server. Only EINTR is worth retrying. */
		if (errno == EAGAIN) {
			return doError("read (no reply from server)", -ETIMEDOUT);
		}
		if (errno != EINTR) {
			return doError("read", -errno);
		}
	}

	if ((NTP_MODE(pkt->li_vn_mode) != NTP_MODE_SERVER && NTP_MODE(pkt->li_vn_mode) != NTP_MODE_PASSIVE) || pkt->stratum >= 16) {
		return doError("ntpclient_gettimepacket", -EPROTO);
	}

	return EOK;
}


static int ntpclient_settime(struct sntp_pkt_s *pkt)
{
	struct timeval tv_new, tv_old;

	if (gettimeofday(&tv_old, NULL) < 0) {
		return doError("gettimeofday", -errno);
	}

	pkt->txTm_sec = ntohl(pkt->txTm_sec);
	pkt->txTm_frac = ntohl(pkt->txTm_frac);

	tv_new.tv_sec = pkt->txTm_sec - NTP_JAN1970_DELTA;
	tv_new.tv_usec = FRAC_TO_USEC(pkt->txTm_frac);

	if (settimeofday(&tv_new, NULL) < 0) {
		return doError("settimeofday", -errno);
	}

	printf("System time in UTC was %s", ctime(&tv_old.tv_sec));
	printf("System time set to UTC %s", ctime(&tv_new.tv_sec));

	return EOK;
}


/* One full attempt: resolve, exchange, set the clock. Returns EOK or -errno. */
static int ntpclient_syncOnce(const char *host, unsigned int timeout)
{
	struct sntp_pkt_s pkt;
	int sockfd, err;

	sockfd = ntpclient_connect(host, timeout);
	if (sockfd < 0) {
		return sockfd;
	}

	err = ntpclient_gettimepacket(sockfd, &pkt);
	close(sockfd);
	if (err < 0) {
		return err;
	}

	return ntpclient_settime(&pkt);
}


static void psh_ntpclientInfo(void)
{
	printf("set the system's date from a remote host");
}

static void psh_ntpclientUsage(void)
{
	printf("Usage: ntpclient [options]\n"
		   "  -h:  prints help\n"
		   "  -s:  ntp server address (default: /etc/ntp.conf, else pool.ntp.org)\n"
		   "  -t:  seconds to wait for the reply (default %u, 0 waits forever)\n"
		   "  -w:  keep retrying for this many seconds before giving up (default 0,\n"
		   "       i.e. a single attempt) -- use it when the network may still be\n"
		   "       coming up, e.g. right after boot\n",
		NTP_RECV_TIMEOUT_S);
}


/* Read the server from /etc/ntp.conf when -s was not given: one `server=<host>`
 * line (or a bare hostname), '#' comments and surrounding whitespace ignored.
 * Mirrors the /etc/wifi.conf convention so a shipped image can be configured
 * without editing the boot script. */
static int ntpclient_confServer(char *out, size_t outsz)
{
	FILE *f = fopen("/etc/ntp.conf", "r");
	char line[160];
	int got = -1;

	if (f == NULL) {
		return -1;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char *p = line, *v, *e;

		while ((*p == ' ') || (*p == '\t')) {
			p++;
		}
		if ((*p == '#') || (*p == '\0') || (*p == '\n')) {
			continue;
		}

		v = strchr(p, '=');
		v = (v != NULL) ? (v + 1) : p;
		while ((*v == ' ') || (*v == '\t')) {
			v++;
		}
		for (e = v + strlen(v) - 1; (e >= v) && ((*e == '\n') || (*e == '\r') || (*e == ' ') || (*e == '\t')); e--) {
			*e = '\0';
		}
		if (*v != '\0') {
			int n = snprintf(out, outsz, "%s", v);
			got = ((n > 0) && ((size_t)n < outsz)) ? 0 : -1;
		}
		break;
	}

	fclose(f);
	return got;
}


static int psh_ntpclientMain(int argc, char **argv)
{
	int opt;
	char confhost[128];
	const char *ntp_host = NULL;
	unsigned int timeout = NTP_RECV_TIMEOUT_S;
	unsigned long window = 0;
	time_t deadline;
	char *end;

	while ((opt = getopt(argc, argv, "s:t:w:h")) != -1) {
		switch (opt) {
			case 's':
				ntp_host = optarg;
				break;

			case 't': {
				unsigned long val = strtoul(optarg, &end, 10);
				if ((*end != '\0') || (val > 3600UL)) {
					fprintf(stderr, "ntpclient: bad timeout '%s'\n", optarg);
					return EXIT_FAILURE;
				}
				timeout = (unsigned int)val;
				break;
			}

			case 'w': {
				window = strtoul(optarg, &end, 10);
				if ((*end != '\0') || (window > 3600UL)) {
					fprintf(stderr, "ntpclient: bad wait window '%s'\n", optarg);
					return EXIT_FAILURE;
				}
				break;
			}

			default:
				/* fall-through */
			case 'h':
				psh_ntpclientUsage();
				return EXIT_SUCCESS;
		}
	}

	if (ntp_host == NULL) {
		ntp_host = (ntpclient_confServer(confhost, sizeof(confhost)) == 0) ? confhost : "pool.ntp.org";
	}

	/* time() runs from boot when the clock is unset, so it is still a usable
	 * stopwatch for the window; a successful sync exits before we consult it. */
	deadline = time(NULL) + (time_t)window;
	ntpclient_silent = (window > 0UL) ? 1 : 0;

	for (;;) {
		if (ntpclient_syncOnce(ntp_host, timeout) == EOK) {
			return EXIT_SUCCESS;
		}

		if (time(NULL) >= deadline) {
			break;
		}
		sleep(NTP_RETRY_INTERVAL_S);
	}

	/* Say what the consequence is, not just that a syscall failed: an unset
	 * clock silently breaks TLS certificate validity and stamps every file the
	 * system writes with the epoch. */
	fprintf(stderr, "ntpclient: clock NOT set (no reply from %s) -- TLS will fail "
		"and file timestamps will be wrong until it is\n", ntp_host);

	return EXIT_FAILURE;
}


void __attribute__((constructor)) ntpclient_registerapp(void)
{
	static psh_appentry_t app = { .name = "ntpclient", .run = psh_ntpclientMain, .info = psh_ntpclientInfo };
	psh_registerapp(&app);
}
