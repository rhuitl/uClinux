#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>

#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_eql.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/route.h>

#include <netinet/in.h>
#include <arpa/inet.h>

/* The following portions are extracted from the netkit-base ping sources,
   and come under this copyright: */

/* 
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
int
in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

#if defined(__GLIBC__) && (__GLIBC__ >= 2)
#define icmphdr			icmp
#define ICMP_DEST_UNREACH	ICMP_UNREACH
#define ICMP_NET_UNREACH	ICMP_UNREACH_NET
#define ICMP_HOST_UNREACH	ICMP_UNREACH_HOST
#define ICMP_PORT_UNREACH	ICMP_UNREACH_PORT
#define ICMP_PROT_UNREACH	ICMP_UNREACH_PROTOCOL
#define ICMP_FRAG_NEEDED	ICMP_UNREACH_NEEDFRAG
#define ICMP_SR_FAILED		ICMP_UNREACH_SRCFAIL
#define ICMP_NET_UNKNOWN	ICMP_UNREACH_NET_UNKNOWN
#define ICMP_HOST_UNKNOWN	ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_HOST_ISOLATED	ICMP_UNREACH_ISOLATED
#define ICMP_NET_UNR_TOS	ICMP_UNREACH_TOSNET
#define ICMP_HOST_UNR_TOS	ICMP_UNREACH_TOSHOST
#define ICMP_SOURCE_QUENCH	ICMP_SOURCEQUENCH
#define ICMP_REDIR_NET		ICMP_REDIRECT_NET
#define ICMP_REDIR_HOST		ICMP_REDIRECT_HOST
#define ICMP_REDIR_NETTOS	ICMP_REDIRECT_TOSNET
#define ICMP_REDIR_HOSTTOS	ICMP_REDIRECT_TOSHOST
#define ICMP_TIME_EXCEEDED	ICMP_TIMXCEED
#define ICMP_EXC_TTL		ICMP_TIMXCEED_INTRANS
#define ICMP_EXC_FRAGTIME	ICMP_TIMXCEED_REASS
#define	ICMP_PARAMETERPROB	ICMP_PARAMPROB
#define ICMP_TIMESTAMP		ICMP_TSTAMP
#define ICMP_TIMESTAMPREPLY	ICMP_TSTAMPREPLY
#define ICMP_INFO_REQUEST	ICMP_IREQ
#define ICMP_INFO_REPLY		ICMP_IREQREPLY
#else
#define ICMP_MINLEN	28
#define inet_ntoa(x) inet_ntoa(*((struct in_addr *)&(x)))
#endif


#define	DEFDATALEN	(64 - 8)	/* default data length */
#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	MAXPACKET	(65536 - 60 - 8)/* max packet size */
#define	MAXWAIT		10		/* max seconds to wait for response */
#define	NROUTES		9		/* number of record route slots */

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

/* various options */
int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100

/* multicast options */
int moptions;
#define MULTICAST_NOLOOP	0x001
#define MULTICAST_TTL		0x002
#define MULTICAST_IF		0x004

#if !defined(__GLIBC__) || (__GLIBC__ < 2)
#define icmp_type type
#define icmp_code code
#define icmp_cksum checksum
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
#define icmp_gwaddr un.gateway
#endif /* __GLIBC__ */

#define ip_hl ihl
#define ip_v version
#define ip_tos tos
#define ip_len tot_len
#define ip_id id
#define ip_off frag_off
#define ip_ttl ttl
#define ip_p protocol
#define ip_sum check
#define ip_src saddr
#define ip_dst daddr

int transmit_ping(int socket, int ident, int sequence, int timing, unsigned char * outpack, int datalen, struct sockaddr * whereto, int wherelen)
{
	register struct icmphdr *icp;
	register int cc;
	int i;

	icp = (struct icmphdr *)outpack;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = sequence;
	icp->icmp_id = ident;			/* ID */

	if (timing)
		(void)gettimeofday((struct timeval *)&outpack[8],
		    (struct timezone *)NULL);

	cc = datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->icmp_cksum = in_cksum((u_short *)icp, cc);

	i = sendto(socket, (char *)outpack, cc, 0, whereto,
	    wherelen);
	   
	/*printf("sendto=%d, errno=%d\n", i, errno);*/
	    
	return i;
}

int receive_ping(int socket, int ident, int seq, unsigned char * packet, int datalen, struct sockaddr * from, int * fromlen)
{
	register struct icmphdr *icp;
	struct iphdr *ip;
	int hlen;
	int cc;
	int orig_fromlen = fromlen ? *fromlen : 0;
	int packlen = datalen+28;
	
	if (fromlen) 
		*fromlen = orig_fromlen;
	
	cc = recvfrom(socket, (char *)packet, packlen, 0,
	    from, fromlen);

	/*printf("recvfrom=%d, errno=%d\n", cc, errno);*/
	    
	if (cc < 0)
		return cc;
	
	/* Check the IP header */
	ip = (struct iphdr *)packet;
	hlen = ip->ip_hl << 2;
	if (cc < datalen + ICMP_MINLEN) {
		/* weird */
		printf("too short (wanted at least %d bytes, got %d)\n",
			datalen+ ICMP_MINLEN, cc);
		return -1;
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(packet + hlen);
	if (icp->icmp_type == ICMP_ECHOREPLY) {
		/* not really needed: any response is good enough */
		/*if (icp->icmp_seq != seq)
			return -1;*/
		/* this happens if more then one ping is going */
		if (icp->icmp_id != ident) {
			printf("id was wrong (wanted %d, got %d)\n",
				ident, icp->icmp_id);
			return -1;	/* 'Twas not our ECHO */
		}
		return 0;
	} else {
		/* this happens easily if something is pinging us,
		   for example */
		/*printf("Not an echoreply (wanted type %d, got %d)\n",
			ICMP_ECHOREPLY, icp->icmp_type);*/
		return -1; /* Not an ECHOREPLY */
	}
}

extern int done;

/* loop until timeout seconds go by without a ping response */
void pinger(int fd, int timeout, struct sockaddr * whereto, int wherelen)
{
	int ident = getpid() & 0xffff;
	int seq = 0;
	int missed = 0;
	unsigned char packet[28];
	
	
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd == -1) {
		/*printf("couldn't get raw socket\n");*/
		return;
	}
	
	if (timeout < 1)
		timeout = 1;
		
	while (missed < 2) {
		int s;
		fd_set rfds;
		struct timeval tv;
		
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		seq++;
		/*printf("Sending ping, seq=%d, id=%d\n", seq, ident);*/
		transmit_ping(fd, ident, seq, 0, packet, 0, whereto, wherelen);
		
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		/* sleep till we get a response, or timeout */
		for (;;) {
			if (done)
				break;

			s = select(fd+1, &rfds, 0, 0, &tv);
			/*printf("Got something, with %d.%06.6d seconds remaining\n",
				tv.tv_sec, tv.tv_usec);*/

			if (done)
				break;
			if (s>0) {
				/* was it a useful response? */
				if (receive_ping(fd, ident, seq, packet, 0, 0, 0)<0)
					/* no, so keep waiting. Maybe the
					   response is still in the queue. */
					continue;
				/*printf("Got a pong\n");*/
				missed = 0;
				break;
			} else if (s==0) {
				missed++;
				/*printf("No response, have missed %d\n", missed);*/
				break;
			}
		}

		if (done)
			break;
		/* sleep off any remaining time */
		select(0, 0,0,0, &tv);
		if (done)
			break;

	}
}
