/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if 0
static char sccsid[] = "@(#)tftp.c	5.7 (Berkeley) 6/29/88";
#endif /* not lint */

/* Many bug fixes are from Jim Guyton <guyton@rand-unix> */

/*
 * TFTP User Program -- Protocol Machines
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <arpa/tftp.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <setjmp.h>
#include <unistd.h>

#include "exit_codes.h"
#include "netflash.h"
#include "tftp.h"

static int tftpmakerequest(int request, char *name, struct tftphdr *tp, char *mode);
static void tftpnak(int error);
static void tftpstartclock(void);
static void tftptpacket(char *s, struct tftphdr *tp, int n);
static void tftpstopclock(void);
static void tftpprintstats(char *direction, unsigned long amount, char *join, char *name);

extern  struct sockaddr_in tftpsin;         /* filled in by main */
extern  int     tftpf;                      /* the opened socket */
extern  int     tftptrace;
extern  int     tftpverbose;
extern  int     tftprexmtval;
extern  int     tftpmaxtimeout;

extern struct tftphdr *tftpw_init(void);

#define PKTSIZE    SEGSIZE+4
char    tftpackbuf[PKTSIZE];
int	tftptimeout;
sigjmp_buf	tftptimeoutbuf;

static
void tftptimer(int signo)
{

	signal(SIGALRM, tftptimer);
	tftptimeout += tftprexmtval;
	if (tftptimeout >= tftpmaxtimeout) {
		printf("Transfer timed out.\n");
		errno = ETIMEDOUT;
		siglongjmp(tftptimeoutbuf, -1);
	}
	siglongjmp(tftptimeoutbuf, 1);
}

#if 0
/*
 * Send the requested file.
 */
tftpsendfile(fd, name, mode)
	int fd;
	char *name;
	char *mode;
{
	register struct tftphdr *ap;       /* data and ack packets */
	struct tftphdr *r_init(), *dp;
	register int block = 0, size, n;
	register unsigned long amount = 0;
	struct sockaddr_in from;
	socklen_t fromlen;
	int convert;            /* true if doing nl->crlf conversion */
	FILE *file;

	tftpstartclock();           /* start stat's clock */
	dp = tftpr_init();          /* reset fillbuf/read-ahead code */
	ap = (struct tftphdr *)tftpackbuf;
	file = fdopen(fd, "r");
	convert = !strcmp(mode, "netascii");

	signal(SIGALRM, tftptimer);
	do {
		if (block == 0)
			size = tftpmakerequest(WRQ, name, dp, mode) - 4;
		else {
		/*      size = read(fd, dp->th_data, SEGSIZE);   */
			size = tftpreadit(file, &dp, convert);
			if (size < 0) {
				tftpnak(errno + 100);
				break;
			}
			dp->th_opcode = htons((u_short)DATA);
			dp->th_block = htons((u_short)block);
		}
		tftptimeout = 0;
		if(sigsetjmp(tftptimeoutbuf, 1) < 0){
			printf("Exiting through timeout\n");
			exit(TF_TIMEOUT);
		}
send_data:
		if (tftptrace)
			tftptpacket("sent", dp, size + 4);
		n = sendto(tftpf, dp, size + 4, 0, (struct sockaddr *)&tftpsin,
				sizeof (tftpsin));
		if (n != size + 4) {
			perror("tftp: sendto");
			goto abort;
		}
		tftpread_ahead(file, convert);
		for ( ; ; ) {
			alarm(tftprexmtval);
			do {
				fromlen = sizeof (from);
				n = recvfrom(tftpf, tftpackbuf,
				    sizeof (tftpackbuf), 0,
				    (struct sockaddr *)&from, &fromlen);
			} while (n <= 0);
			alarm(0);
			if (n < 0) {
				perror("tftp: recvfrom");
				goto abort;
			}
			tftpsin.sin_port = from.sin_port;   /* added */
			if (tftptrace)
				tftptpacket("received", ap, n);
			/* should verify packet came from server */
			ap->th_opcode = ntohs(ap->th_opcode);
			ap->th_block = ntohs(ap->th_block);
			if (ap->th_opcode == ERROR) {
				printf("Error code %d: %s\n", ap->th_code,
					ap->th_msg);
				goto abort;
			}
			if (ap->th_opcode == ACK) {
				int j;

				if (ap->th_block == block) {
					break;
				}
				/* On an error, try to synchronize
				 * both sides.
				 */
				j = tftpsynchnet(tftpf);
				if (j && tftptrace) {
					printf("discarded %d packets\n",
							j);
				}
				if (ap->th_block == (block-1)) {
					goto send_data;
				}
			}
		}
		if (block > 0)
			amount += size;
		block++;
	} while (size == SEGSIZE || block == 1);
abort:
	fclose(file);
	tftpstopclock();
	if (amount > 0)
		tftpprintstats("Sent", amount, "to", name);
}
#endif

/*
 * Receive a file.
 */
void
tftprecvfile(fd, name, mode)
	int fd;
	char *name;
	char *mode;
{
	register struct tftphdr *ap;
	struct tftphdr *dp, *w_init();
	register int n, size;
	u_short block = 1;
	unsigned long amount = 0;
	struct sockaddr_in from;
	socklen_t fromlen;
	int firsttrip = 1;
	FILE *file;
	int convert;                    /* true if converting crlf -> lf */

	tftpstartclock();
	dp = tftpw_init();
	ap = (struct tftphdr *)tftpackbuf;
	file = local_fdopen(fd, "w");
	convert = !strcmp(mode, "netascii");

	signal(SIGALRM, tftptimer);
	do {
		if (firsttrip) {
			size = tftpmakerequest(RRQ, name, ap, mode);
			firsttrip = 0;
		} else {
			ap->th_opcode = htons((u_short)ACK);
			ap->th_block = htons(block);
			size = 4;
			block++;
		}
		tftptimeout = 0;
		if(sigsetjmp(tftptimeoutbuf, 1)<0){
			exit(TF_TIMEOUT);
		}
send_ack:
		if (tftptrace)
			tftptpacket("sent", ap, size);
		if (sendto(tftpf, tftpackbuf, size, 0, (struct sockaddr *)&tftpsin,
		    sizeof (tftpsin)) != size) {
			alarm(0);
			perror("tftp: sendto");
			goto abort;
		}
		tftpwrite_behind(file, convert);
		for ( ; ; ) {
			alarm(tftprexmtval);
			do  {
				fromlen = sizeof (from);
				n = recvfrom(tftpf, dp, PKTSIZE, 0,
				    (struct sockaddr *)&from, &fromlen);
			} while (n <= 0);
			alarm(0);
			if (n < 0) {
				perror("tftp: recvfrom");
				goto abort;
			}
			tftpsin.sin_port = from.sin_port;   /* added */
			if (tftptrace)
				tftptpacket("received", dp, n);
			/* should verify client address */
			dp->th_opcode = ntohs(dp->th_opcode);
			dp->th_block = ntohs(dp->th_block);
			if (dp->th_opcode == ERROR) {
				printf("Error code %d: %s\n", dp->th_code,
					dp->th_msg);
				goto abort;
			}
			if (dp->th_opcode == DATA) {
				int j;

				if (dp->th_block == block) {
					break;          /* have next packet */
				}
				/* On an error, try to synchronize
				 * both sides.
				 */
				j = tftpsynchnet(tftpf);
				if (j && tftptrace) {
					printf("discarded %d packets\n", j);
				}
				if (dp->th_block == (block-1)) {
					goto send_ack;  /* resend ack */
				}
			}
		}
	/*      size = write(fd, dp->th_data, n - 4); */
		size = tftpwriteit(file, &dp, n - 4, convert);
		if (size < 0) {
			tftpnak(errno + 100);
			break;
		}
		amount += size;
	} while (size == SEGSIZE);
abort:                                          /* ok to ack, since user */
	ap->th_opcode = htons((u_short)ACK);    /* has seen err msg */
	ap->th_block = htons(block);
	(void) sendto(tftpf, tftpackbuf, 4, 0, (struct sockaddr *) &tftpsin,
			sizeof (tftpsin));
	tftpwrite_behind(file, convert);            /* flush last buffer */
	local_fclose(file);
	tftpstopclock();
	if (amount > 0)
		tftpprintstats("Received", amount, "from", name);
}

static int
tftpmakerequest(request, name, tp, mode)
	int request;
	char *name, *mode;
	struct tftphdr *tp;
{
	register char *cp;

	tp->th_opcode = htons((u_short)request);
	cp = tp->th_stuff;
	strcpy(cp, name);
	cp += strlen(name);
	*cp++ = '\0';
	strcpy(cp, mode);
	cp += strlen(mode);
	*cp++ = '\0';
	return (cp - (char *)tp);
}

struct errmsg {
	int	e_code;
	char	*e_msg;
} tftperrmsgs[] = {
	{ EUNDEF,	"Undefined error code" },
	{ ENOTFOUND,	"File not found" },
	{ EACCESS,	"Access violation" },
	{ ENOSPACE,	"Disk full or allocation exceeded" },
	{ EBADOP,	"Illegal TFTP operation" },
	{ EBADID,	"Unknown transfer ID" },
	{ EEXISTS,	"File already exists" },
	{ ENOUSER,	"No such user" },
	{ -1,		0 }
};

/*
 * Send a nak packet (error message).
 * Error code passed in is one of the
 * standard TFTP codes, or a UNIX errno
 * offset by 100.
 */
static void
tftpnak(error)
	int error;
{
	register struct tftphdr *tp;
	int length;
	register struct errmsg *pe;

	tp = (struct tftphdr *)tftpackbuf;
	tp->th_opcode = htons((u_short)ERROR);
	tp->th_code = htons((u_short)error);
	for (pe = tftperrmsgs; pe->e_code >= 0; pe++)
		if (pe->e_code == error)
			break;
	if (pe->e_code < 0) {
#ifdef EMBED
		pe->e_msg = "error";
#else
		pe->e_msg = strerror(error - 100);
#endif
		tp->th_code = EUNDEF;
	}
	strcpy(tp->th_msg, pe->e_msg);
	length = strlen(pe->e_msg) + 4;
	if (tftptrace)
		tftptpacket("sent", tp, length);
	if (sendto(tftpf, tftpackbuf, length, 0, (struct sockaddr *) &tftpsin,
			sizeof (tftpsin)) != length)
		perror("nak");
}

static void
tftptpacket(s, tp, n)
	char *s;
	struct tftphdr *tp;
	int n;
{
	static char *opcodes[] =
	   { "#0", "RRQ", "WRQ", "DATA", "ACK", "ERROR" };
	register char *cp, *file;
	u_short op = ntohs(tp->th_opcode);

	if (op < RRQ || op > ERROR)
		printf("%s opcode=%x ", s, op);
	else
		printf("%s %s ", s, opcodes[op]);
	switch (op) {

	case RRQ:
	case WRQ:
		n -= 2;
		file = cp = tp->th_stuff;
		cp = strchr(cp, '\0');
		printf("<file=%s, mode=%s>\n", file, cp + 1);
		break;

	case DATA:
		printf("<block=%d, %d bytes>\n", ntohs(tp->th_block), n - 4);
		break;

	case ACK:
		printf("<block=%d>\n", ntohs(tp->th_block));
		break;

	case ERROR:
		printf("<code=%d, msg=%s>\n", ntohs(tp->th_code), tp->th_msg);
		break;
	}
}

struct timeval tftptstart;
struct timeval tftptstop;
struct timezone tftpzone;

static void
tftpstartclock() {
	gettimeofday(&tftptstart, &tftpzone);
}

static void
tftpstopclock() {
	gettimeofday(&tftptstop, &tftpzone);
}

static void
tftpprintstats(direction, amount, join, name)
char *direction;
unsigned long amount;
char *join;
char *name;
{
#ifdef EMBED
	if (tftpverbose)
		printf("%s %d bytes %s %s\n", direction, amount, join, name);
#else
	double delta;
			/* compute delta in 1/10's second units */
	delta = ((tftptstop.tv_sec*10.)+(tftptstop.tv_usec/100000)) -
		((tftptstart.tv_sec*10.)+(tftptstart.tv_usec/100000));
	delta = delta/10.;      /* back to seconds */
	printf("%s %d bytes in %.1f seconds", direction, amount, delta);
	if ((tftpverbose) && (delta >= 0.1))
			printf(" [%.0f bits/sec]", (amount*8.)/delta);
	putchar('\n');
#endif
}

