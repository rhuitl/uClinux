/* resolv.c: DNS Resolver
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>

#define DNS_SERVICE 53
#define MAX_RECURSE 5
#define REPLY_TIMEOUT 10
#define MAX_RETRIES 15

#undef DEBUG
#ifdef DEBUG
#define DPRINTF(X,args...) printf(X,##args)
#else
#define DPRINTF(X,args...)
#endif /* DEBUG */


extern struct hostent * get_hosts_byname(const char * name);
extern struct hostent * get_hosts_byaddr(const char * addr, int len, int type);


#ifdef L_encodeh
int encode_header(struct resolv_header * h, unsigned char * dest, int maxlen)
{
	if (maxlen < 12)
		return -1;

	dest[0] = (h->id & 0xff00) >> 8;
	dest[1] = (h->id & 0x00ff) >> 0;
	dest[2] = (h->qr ? 0x80 : 0) |
		  ((h->opcode & 0x0f) << 3) |
		  (h->aa ? 0x04 : 0) |
		  (h->tc ? 0x02 : 0) |
		  (h->rd ? 0x01 : 0);
	dest[3] = (h->ra ? 0x80 : 0) |
		  (h->rcode & 0x0f);
	dest[4] = (h->qdcount & 0xff00) >> 8;
	dest[5] = (h->qdcount & 0x00ff) >> 0;
	dest[6] = (h->ancount & 0xff00) >> 8;
	dest[7] = (h->ancount & 0x00ff) >> 0;
	dest[8] = (h->nscount & 0xff00) >> 8;
	dest[9] = (h->nscount & 0x00ff) >> 0;
	dest[10] = (h->arcount & 0xff00) >> 8;
	dest[11] = (h->arcount & 0x00ff) >> 0;
	
	return 12;
}
#endif

#ifdef L_decodeh
int decode_header(unsigned char * data, struct resolv_header * h)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0f;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0f;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];
	
	return 12;
}
#endif

#ifdef L_encoded
/* Encode a dotted string into nameserver transport-level encoding.
   This routine is fairly dumb, and doesn't attempt to compress
   the data */
   
int encode_dotted(const char * dotted, unsigned char * dest, int maxlen)
{
	int used=0;

	while(dotted && *dotted) {
		char * c = strchr(dotted, '.');
		int l = c ? c - dotted : strlen(dotted);
		
		if (l >= (maxlen-used-1))
			return -1;
		
		dest[used++] = l;
		memcpy(dest+used, dotted, l);
		used += l;
		
		if (c)
			dotted = c+1;
		else
			break;
	}
	
	if (maxlen < 1)
		return -1;
		
	dest[used++] = 0;
	
	return used;
}
#endif

#ifdef L_decoded
/* Decode a dotted string from nameserver transport-level encoding.
   This routine understands compressed data. */

int decode_dotted(const unsigned char * data, int offset, 
	char * dest, int maxlen)
{
	int l;
	int measure=1;
	int total = 0;
	int used=0;
	
	if (!data)
		return -1;
	
	while ((measure && total++), (l=data[offset++])) {
		
		if ((l & 0xc0) == (0xc0)) {
			if (measure)
				total++;
			/* compressed item, redirect */
			offset = ((l & 0x3f) << 8) | data[offset];
			measure = 0;
			continue;
		}
	
		if ((used+l+1) >= maxlen)
			return -1;
			
		memcpy(dest+used, data+offset, l);
		offset += l;
		used += l;
		if (measure)
			total += l;
		
		if (data[offset] != 0)
			dest[used++] = '.';
		else
			dest[used++] = '\0';
	}
	
	DPRINTF("Total decode len = %d\n", total);
	
	return total;
}
#endif

#ifdef L_lengthd

int length_dotted(const unsigned char * data, int offset)
{
	int orig_offset = offset;
	int l;
	
	if (!data)
		return -1;
	
	while ((l=data[offset++])) {
		
		if ((l & 0xc0) == (0xc0)) {
			offset++;
			break;
		}
		
		offset += l;
	}
	
	return offset-orig_offset;
}
#endif

#ifdef L_encodeq
int encode_question(struct resolv_question * q,
	unsigned char * dest, int maxlen)
{
	int i;

	i = encode_dotted(q->dotted, dest, maxlen);
	if (i < 0)
		return i;
	
	dest += i;
	maxlen -= i;
	
	if (maxlen < 4)
		return -1;
	
	dest[0] = (q->qtype & 0xff00) >> 8;
	dest[1] = (q->qtype & 0x00ff) >> 0;
	dest[2] = (q->qclass & 0xff00) >> 8;
	dest[3] = (q->qclass & 0x00ff) >> 0;
	
	return i+4;
}
#endif

#ifdef L_decodeq
int decode_question(unsigned char * message, int offset,
	struct resolv_question * q)
{
	char temp[256];
	int i;

	i = decode_dotted(message, offset, temp, 256);
	if (i < 0)
		return i;
		
	offset += i;
	
	q->dotted = strdup(temp);
	q->qtype  = (message[offset+0] << 8) | message[offset+1];
	q->qclass = (message[offset+2] << 8) | message[offset+3];
	
	return i+4;
}
#endif

#ifdef L_lengthq
int length_question(unsigned char * message, int offset)
{
	int i;

	i = length_dotted(message, offset);
	if (i < 0)
		return i;
	
	return i+4;
}
#endif

#ifdef L_encodea
int encode_answer(struct resolv_answer * a,
	unsigned char * dest, int maxlen)
{
	int i;

	i = encode_dotted(a->dotted, dest, maxlen);
	if (i < 0)
		return i;
	
	dest += i;
	maxlen -= i;
	
	if (maxlen < (10+a->rdlength))
		return -1;
	
	*dest++ = (a->atype & 0xff00) >> 8;
	*dest++ = (a->atype & 0x00ff) >> 0;
	*dest++ = (a->aclass & 0xff00) >> 8;
	*dest++ = (a->aclass & 0x00ff) >> 0;
	*dest++ = (a->ttl & 0xff000000) >> 24;
	*dest++ = (a->ttl & 0x00ff0000) >> 16;
	*dest++ = (a->ttl & 0x0000ff00) >> 8;
	*dest++ = (a->ttl & 0x000000ff) >> 0;
	*dest++ = (a->rdlength & 0xff00) >> 8;
	*dest++ = (a->rdlength & 0x00ff) >> 0;
	memcpy(dest, a->rdata, a->rdlength);
	
	return i+10+a->rdlength;
}
#endif

#ifdef L_decodea
int decode_answer(unsigned char * message, int offset,
	struct resolv_answer * a)
{
	char temp[256];
	int i;

	i = decode_dotted(message, offset, temp, 256);
	if (i < 0)
		return i;
	
	message += offset+i;
	
	a->dotted = strdup(temp);
	a->atype  = (message[0] << 8) | message[1]; message += 2;
	a->aclass = (message[0] << 8) | message[1]; message += 2;
	a->ttl = (message[0] << 24) |
		 (message[1] << 16) |
	 	 (message[2] << 8) |
	 	 (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1]; message += 2;
	a->rdata = message;
	a->rdoffset = offset+i+10;
	
	DPRINTF("i=%d,rdlength=%d\n", i, a->rdlength);
	
	return i+10+a->rdlength;
}
#endif

#ifdef L_encodep
int encode_packet(struct resolv_header * h,
	struct resolv_question ** q,
	struct resolv_answer ** an,
	struct resolv_answer ** ns,
	struct resolv_answer ** ar,
	unsigned char * dest, int maxlen)
{
	int i, total=0;
	int j;

	i = encode_header(h, dest, maxlen);
	if (i < 0)
		return i;
	
	dest += i;
	maxlen -= i;
	total += i;
	
	for(j=0;j<h->qdcount;j++) {
		i = encode_question(q[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}

	for(j=0;j<h->ancount;j++) {
		i = encode_answer(an[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	for(j=0;j<h->nscount;j++) {
		i = encode_answer(ns[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	for(j=0;j<h->arcount;j++) {
		i = encode_answer(ar[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	
	return total;
}
#endif

#ifdef L_decodep
int decode_packet(unsigned char * data, struct resolv_header * h)
{
	return decode_header(data, h);
}
#endif

#ifdef L_formquery
int form_query(int id, const char * name, int type, unsigned char * packet, int maxlen)
{
	struct resolv_header h;
	struct resolv_question q;
	int i,j;
	
	memset(&h, 0, sizeof(h));
	h.id = id;
	h.qdcount = 1;
	
	q.dotted = (char*)name;
	q.qtype = type;
	q.qclass = 1 /*CLASS_IN*/;
	
	i = encode_header(&h, packet, maxlen);
	if (i < 0)
		return i;
	
	j = encode_question(&q, packet+i, maxlen-i);
	if (j < 0)
		return j;

	return i+j;
}
#endif

#ifdef L_dnslookup

/* SURF random number generator -
   The SURF random number generator was taken from djbdns-1.05, by 
   Daniel J Berstein, which is public domain. */

typedef unsigned int uint32;

static uint32 seed[32];
static uint32 in[12];
static uint32 out[8];

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  uint32 t[12]; uint32 x; uint32 sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

unsigned short dns_rand16(void)
{
  static int outleft = 0;

  if (!outleft) {
    if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
    surf();
    outleft = 8;
  }

  return (unsigned short) out[--outleft];
}

int dns_caught_signal = 0;
void dns_catch_signal(int signo) {
	dns_caught_signal = 1;
}	

int dns_lookup(const char * name, int type, int nscount, const char ** nsip,
	unsigned char ** outpacket, struct resolv_answer * a)
{
	int sent_id;
	int i,j,len;
	int fd;
	int pos;
	static int ns = 0;
	struct sockaddr_in sa;
	int oldalarm;
	struct sigaction alarm_act, old_alarm_act;
	struct resolv_header h;
	struct resolv_question q;
	int retries = 0;
	unsigned char * packet = malloc(512);
	static init_rand = 0;
	
	if (!packet)
		goto fail1;
		
	DPRINTF("Looking up type %d answer for '%s'\n", type, name);

	if (!init_rand) {
		struct timeval tv;
		int fd;
		int fail = 0;

		/* Just seed the RNG once only, even if we can't get a good source */
		init_rand = 1;

		fd = open("/dev/urandom", O_RDONLY);
		if (fd != -1) {
			if (read(fd, (unsigned char *)&seed, sizeof(seed)) != sizeof(seed)) {
				fail = 1;
			}
			if (read(fd, (unsigned char *)&in, sizeof(in)) != sizeof(in)) {
				fail = 1;
			}
			close(fd);
		}
		if ((fd == -1) || (fail != 0)) {
			/* Failure reading urandom - just try our best to get some entropy */
			uint32 r;
			gettimeofday(&tv, NULL);
			r = (tv.tv_usec << 16) ^ tv.tv_sec ^ getpid();
			srand(r);

			for (i = 0; i < sizeof(seed) / 4; i++) {
				r = random();
				memcpy(&seed[i], &r, sizeof(uint32));
			}
			for (i = 0; i < sizeof(in) / 4; i++) {
				r = random();
				memcpy(&in[i], &r, sizeof(uint32));
			}
		}
	}
	
	if (!nscount)
		goto fail1;
		
	ns %= nscount; /* make sure round robin "ns" is valid */
	
	fd = -1;
	
	memset(&alarm_act, 0, sizeof(alarm_act));
	alarm_act.sa_handler = dns_catch_signal;
	alarm_act.sa_flags = (SA_ONESHOT | SA_NOMASK | SA_INTERRUPT) &
								~SA_RESTART;

	while (retries++ < MAX_RETRIES) {
	
		if (fd != -1)
			close(fd);

		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
		if (fd==-1)
			goto fail2;
		
	
		memset(packet, 0, 512);

		memset(&h, 0, sizeof(h));
		sent_id = dns_rand16();
		h.id = sent_id;
		h.qdcount = 1;
		h.rd = 1;
		
		DPRINTF("encoding header\n");

		i = encode_header(&h, packet, 512);
		if (i < 0)
			goto fail3;

		q.dotted = (char*)name;
		q.qtype = type;
		q.qclass = 1 /*CLASS_IN*/;
	
		j = encode_question(&q, packet+i, 512-i);
		if (j < 0)
			goto fail3;
	
		len = i+j;

		DPRINTF("On try %d, sending query to port %d of machine %s\n",
			retries, DNS_SERVICE, nsip[ns]);

		sa.sin_family = AF_INET;
		sa.sin_port = htons(DNS_SERVICE);
		sa.sin_addr.s_addr = inet_addr(nsip[ns]);

		if (connect(fd, (struct sockaddr*)&sa, sizeof(sa))==-1) {
			if (errno == ENETUNREACH) {
				/* routing error, presume not transient */
				goto tryall;
			} else
				/* retry */
			    goto tryall;
		}
		
		DPRINTF("Transmitting packet of length %d, id=%d, qr=%d\n", 
			len, h.id, h.qr);

		send(fd, packet, len, 0);

		dns_caught_signal = 0;
		oldalarm = alarm(REPLY_TIMEOUT);
		sigaction(SIGALRM, &alarm_act, &old_alarm_act);
	
		i = recv(fd, packet, 512, 0);
		
		alarm(0);
		sigaction(SIGALRM, &old_alarm_act, NULL);
		alarm(oldalarm);
		
		DPRINTF("Timeout=%d, len=%d\n",
			dns_caught_signal, i);
		
		if (dns_caught_signal)
			/* timed out, so retry send and receive,
			   to next nameserver on queue */
			goto again;
		
		if (i < 12)
			/* too short ! */
			goto again;
		
		decode_header(packet, &h);
		
		DPRINTF("id = %d, qr = %d\n",
			h.id, h.qr);
		
		if ((h.id != sent_id) || (!h.qr))
			/* unsolicited */
			goto again;
		
		DPRINTF("Got response (i think)!\n");
		DPRINTF("qrcount=%d,ancount=%d,nscount=%d,arcount=%d\n",
			h.qdcount, h.ancount, h.nscount, h.arcount);
		DPRINTF("opcode=%d,aa=%d,tc=%d,rd=%d,ra=%d,rcode=%d\n",
			h.opcode,h.aa,h.tc,h.rd,h.ra,h.rcode);
		
		if ((h.rcode) || (h.ancount < 1)) {
			/* negative result, not present */
			goto tryall;
		}
			
		pos = 12;

		for(j=0;j<h.qdcount;j++) {
			DPRINTF("Skipping question %d at %d\n", j, pos);
			i = length_question(packet, pos);
			DPRINTF("Length of question %d is %d\n", j, i);
			if (i < 0)
				goto again;
			pos += i;
		}
		DPRINTF("Decoding answer at pos %d\n", pos);
		
		i = decode_answer(packet, pos, a);
		
		if (i<0) {
			DPRINTF("failed decode %d\n", i);
			goto again;
		}
		
		DPRINTF("Answer name = |%s|\n", a->dotted);
		DPRINTF("Answer type = |%d|\n", a->atype);
		
		close(fd);
		
		if (outpacket)
			*outpacket = packet;
		else
			free(packet);
		return (0); /* success! */

	tryall:
		/* if there are other nameservers, give them a go,
		   otherwise return with error */
		if (retries >= nscount)
			break;
	again:
		ns = (ns + 1) % nscount;
		continue;
	}

fail3:	
	close(fd);
fail2:
	free(packet);
fail1:
	return -1;
}
#endif

#ifdef L_resolveaddress

int resolve_address(const char * address, 
	int nscount, const char ** nsip, 
	struct in_addr * in)
{
	unsigned char * packet;
	struct resolv_answer a;
	char temp[256];
	int i;
	int nest=0;
	
	if (!address || !in)
		return -1;
		
	strcpy(temp, address);
	
	for(;;) {
	
		i = dns_lookup(temp, 1, nscount, nsip, &packet, &a);
	
		if (i<0)
			return -1;
	
		free(a.dotted);
		
		if (a.atype == 5) { /* CNAME*/
			i = decode_dotted(packet, a.rdoffset, temp, 256);
			free(packet);
			
			if (i <0)
				return -1;
			if (++nest > MAX_RECURSE)
				return -1;
			continue;
		} else if (a.atype == 1) { /* ADDRESS */
			free(packet);
			break;
		} else {
			free(packet);
			return -1;
		}
	}
	
	if (in)
		memcpy(in, a.rdata, 4);
		
	return 0;
}
#endif

#ifdef L_resolvemailbox

int resolve_mailbox(const char * address, 
	int nscount, const char ** nsip, 
	struct in_addr * in)
{
	struct resolv_answer a;
	unsigned char * packet;
	char temp[256];
	int nest=0;
	int i;
	
	if (!address || !in)
		return -1;
	
	/* look up mail exchange */
	i = dns_lookup(address, 15, nscount, nsip, &packet, &a);
	
	strcpy(temp, address);
	
	if (i>=0) {
		i = decode_dotted(packet, a.rdoffset+2, temp, 256);
		free(packet);
	}
	
	for(;;) {
	
		i = dns_lookup(temp, 1, nscount, nsip, &packet, &a);
	
		if (i<0)
			return -1;
	
		free(a.dotted);
		
		if (a.atype == 5) { /* CNAME*/
			i = decode_dotted(packet, a.rdoffset, temp, 256);
			free(packet);
			if (i<0)
				return i;
			if (++nest > MAX_RECURSE)
				return -1;
			continue;
		} else if (a.atype == 1) { /* ADDRESS */
			free(packet);
			break;
		} else {
			free(packet);
			return -1;
		}
	}

	if (in)
		memcpy(in, a.rdata, 4);
		
	return 0;
}
#endif

extern int nameservers;
extern const char * nameserver[MAXNS];

#ifdef L_opennameservers

int nameservers;
const char *nameserver[MAXNS];

int open_nameservers()
{
	FILE *fp;
	char **arg;
	int i;
	char szBuffer[128];
	char *p;

	if ((fp = fopen("/etc/resolv.conf", "r")) ||
			(fp = fopen("/etc/config/resolv.conf", "r"))) {
		for (i = 0; i < nameservers; i++) {
			if (nameserver[i]) {
				free((void *) nameserver[i]);
				nameserver[i] = NULL;
			}
		}
		nameservers = 0;
		while (fgets(szBuffer, sizeof(szBuffer), fp) != NULL) {
			for (p = szBuffer; *p && isspace(*p); p++)
				/* skip white space */;
			if (*p == '#') /* skip comments */
				continue;
			if (strncmp(p, "nameserver", 10) == 0) {
				p += 10;
				for (; *p && isspace(*p); p++)
					;
				for (i = 0; p[i] && isprint(p[i]); i++)
					;
				p[i] = '\0';
				nameserver[nameservers++] = strdup(p);
			}
			if (nameservers >= MAXNS)
				break;
		}
		fclose(fp);
	}
	return 0;
}
#endif

#ifdef L_closenameservers
void close_nameservers(void) {

	while(nameservers>0) {
		free((void *) nameserver[--nameservers]);
		nameserver[nameservers] = NULL;
	}
}
#endif


#ifdef L_resolvename

char * resolve_name(const char * name, int mailbox)
{
	struct in_addr in;
	int i;
	
	/* shortcut: is it a valid IP address to begin with? */
	if (inet_aton(name, &in))
		return (char *) name;
		
	open_nameservers();
	
	DPRINTF("looking up '%s', mailbox=%d, nameservers=%d\n",
		name, mailbox, nameservers);
	
	if (mailbox)
		i = resolve_mailbox(name, nameservers, nameserver, &in);
	else
		i = resolve_address(name, nameservers, nameserver, &in);
	
	if (i<0)
		return 0;
	
	DPRINTF("success = '%s'\n", inet_ntoa(in));
		
	return inet_ntoa(in);
}
#endif

#ifdef L_gethostbyname

/*
 *  Quick hack to obtain the domain.
 */
char *GetDomainName()
{
	static char *domainName = NULL;
        FILE *fp;
        char **arg;
        int i;
        char szBuffer[128];
        char *p;

        if ((fp = fopen("/etc/resolv.conf", "r")) ||
                        (fp = fopen("/etc/config/resolv.conf", "r"))) {

		if(domainName !=NULL)
			free(domainName);
		domainName = NULL;

                while (fgets(szBuffer, sizeof(szBuffer), fp) != NULL) {
                        for (p = szBuffer; *p && isspace(*p); p++)
                                /* skip white space */;
                        if (*p == '#') /* skip comments */
                                continue;
                        if (strncmp(p, "domain", 6) == 0) {
                                p += 6;
                                for (; *p && isspace(*p); p++)
                                        ;
                                for (i = 0; p[i] && isprint(p[i]); i++)
                                        ;
                                p[i] = '\0';
				domainName =  strdup(p);
                        }
                }
                fclose(fp);
        }
        return domainName;
}
	

struct hostent * gethostbyname(const char * name)
{
	static struct hostent h, *hp;
	static char *namebuf;
	static struct in_addr in;
	static struct in_addr *addr_list[2];
	unsigned char * packet;
	unsigned char *domainName = NULL;
	struct resolv_answer a;
	int i;
	int nest=0;

	if (hp = get_hosts_byname(name)) /* do /etc/hosts first */
		return(hp);

	open_nameservers();
	
	if (!name)
		return NULL;
	
		
	memset(&h, 0, sizeof(h));
	
	if (namebuf == NULL) {
		namebuf = calloc(512, sizeof(char));
		if (namebuf == NULL)
			return NULL;
	}

	addr_list[0] = &in;
	addr_list[1] = 0;
	
	strncpy(namebuf, name, 512);

	/* First check if this is already an address */
	if (inet_aton(name, &in)) {
	    h.h_name = namebuf;
	    h.h_addrtype = AF_INET;
	    h.h_length = sizeof(in);
	    h.h_addr_list = (char **) addr_list;
	    return &h;
	}

	for(;;){
		i = dns_lookup(namebuf, 1, nameservers, nameserver, &packet, &a);
		if (i<0){
			goto lookupDomain;
		}
			
		strcpy(namebuf, a.dotted);
		free(a.dotted);
		if (a.atype == 5) { /* CNAME*/
			i = decode_dotted(packet, a.rdoffset, namebuf, 256);
			free(packet);
			
			if (i <0)
				return 0;
			if (++nest > MAX_RECURSE)
				return 0;
			continue;
		} else if (a.atype == 1) { /* ADDRESS */
			memcpy(&in, a.rdata, sizeof(in));
			h.h_name = namebuf;
			h.h_addrtype = AF_INET;
			h.h_length = sizeof(in);
			h.h_addr_list = (char**)addr_list;
			free(packet);
			break;
		} else {
lookupDomain:
			if(domainName != NULL){
				return 0;
			}
			domainName = GetDomainName();
			if (!domainName)
				return 0;
			strncpy(namebuf, name, 512);
			strncat(namebuf, ".", 512);
			strncat(namebuf, domainName, 512 - 1 - strlen(name));
			continue;
		}
	}
	return &h;
}

#endif

#ifdef L_getnetbyname
struct netent * getnetbyname(const char * name)
{
	return NULL;
}
#endif

#ifdef L_getnetbyaddr
struct netent * getnetbyaddr(long net, int type)
{
	return NULL;
}
#endif

#ifdef L_gethostbyname2
struct hostent * gethostbyname2(const char * name, int af)
{
	return ((af == AF_INET) ? gethostbyname(name) : 0);
}
#endif

#ifdef L_res_init
int res_init()
{
	return(0);
}
#endif

#ifdef L_res_query

#ifndef MIN
#define MIN(x, y)	((x) < (y) ? (x) : (y))
#endif

int res_query(const char *dname, int class, int type,
              unsigned char *answer, int anslen)
{
	static struct in_addr in;
	static struct in_addr *addr_list[2];
	unsigned char * packet;
	struct resolv_answer a;
	int i;
	int nest=0;

	open_nameservers();
	
	if (!dname || class != 1 /* CLASS_IN */)
		return(-1);
		
	i = dns_lookup(dname, type, nameservers, nameserver, &packet, &a);
	
	if (i < 0)
		return(-1);
			
	free(a.dotted);
		
	if (a.atype == type) { /* CNAME*/
		if (anslen && answer)
			memcpy(answer, a.rdata, MIN(anslen, a.rdlength));
		free(packet);
		return(MIN(anslen, a.rdlength));
	}
	free(packet);
	return 0;
}
#endif

#ifdef L_gethostbyaddr

struct hostent * gethostbyaddr(const char * addr, int len, int type)
{
	static struct hostent h, *hp;
	static char *namebuf;
	static struct in_addr in;
	static struct in_addr *addr_list[2];
	unsigned char * packet;
	struct resolv_answer a;
	int i;
	int nest=0;
	
	if (!addr || (len != sizeof(in)) || (type != AF_INET))
		return NULL;

	if (hp = get_hosts_byaddr(addr, len, type)) /* do /etc/hosts first */
		return(hp);

	memcpy(&in.s_addr, addr, len);

	open_nameservers();
		
	memset(&h, 0, sizeof(h));
	
	addr_list[0] = &in;
	addr_list[1] = 0;
	
	if (namebuf == NULL) {
		namebuf = malloc(sizeof(char) * 256);
		if (namebuf == NULL)
			return NULL;
	}
	sprintf(namebuf, "%d.%d.%d.%d.in-addr.arpa",
		(in.s_addr >> 0) & 0xff,
		(in.s_addr >> 8) & 0xff,
		(in.s_addr >> 16) & 0xff,
		(in.s_addr >> 24) & 0xff
		);
	
	for(;;) {
	
		i = dns_lookup(namebuf, 12, nameservers, nameserver, &packet, &a);
	
		if (i<0)
			return 0;
			
		strcpy(namebuf, a.dotted);
		free(a.dotted);
		
		if (a.atype == 5) { /* CNAME*/
			i = decode_dotted(packet, a.rdoffset, namebuf, 256);
			free(packet);
			
			if (i <0)
				return 0;
			
			if (++nest > MAX_RECURSE)
				return 0;

			continue;
		} else if (a.atype == 12) { /* ADDRESS */
			i = decode_dotted(packet, a.rdoffset, namebuf, 256);
			free(packet);
			
			h.h_name = namebuf;
			h.h_addrtype = AF_INET;
			h.h_length = sizeof(in);
			h.h_addr_list = (char**)addr_list;
			break;
		} else {
			free(packet);
			return 0;
		}
	}
		
	return &h;
}
#endif

#ifdef L_getprotobyname
struct protoent __get_proto_by_X_protos[] = {
	{ "ip", NULL, 0 },
	{ "icmp", NULL, 1 },
	{ "tcp", NULL, 6 },
	{ "udp", NULL, 17 },
	{ "raw", NULL, 255 },
	{ NULL, NULL, 0 }
};

struct protoent * getprotobyname(const char * name)
{
	int i;

	for (i = 0; __get_proto_by_X_protos[i].p_name != NULL; i++) {
		if (strcmp(__get_proto_by_X_protos[i].p_name, name) == 0)
			return(&__get_proto_by_X_protos[i]);
	}
	return((struct protoent *) NULL);
}

#endif

#ifdef L_getprotobynumber
extern struct protoent __get_proto_by_X_protos[];

struct protoent * getprotobynumber(int proto) {
	int i;

	for (i = 0; __get_proto_by_X_protos[i].p_name != NULL; i++) {
		if (__get_proto_by_X_protos[i].p_proto == proto)
			return(&__get_proto_by_X_protos[i]);
	}
	return((struct protoent *) NULL);
}

#endif

#ifdef L_read_etc_hosts

struct hostent * read_etc_hosts(const char * name, int ip)
{
	static struct hostent	h;
	static struct in_addr	in;
	static struct in_addr	*addr_list[2];
	static char				*line;
	FILE					*fp;
	char					*cp;
#define		 MAX_ALIAS		5
	char					*alias[MAX_ALIAS];
	int						aliases, i;

	if (line == NULL) {
		line = malloc(sizeof(char) * 80);
		if (line == NULL)
			return NULL;
	}

	if ((fp = fopen("/etc/hosts", "r")) == NULL &&
			(fp = fopen("/etc/config/hosts", "r")) == NULL)
		return((struct hostent *) NULL);

	while (fgets(line, sizeof(char) * 80, fp)) {
		if (cp = strchr(line, '#'))
			*cp = '\0';
		aliases = 0;

		cp = line;
		while (*cp) {
			while (*cp && isspace(*cp))
				*cp++ = '\0';
			if (!*cp)
				continue;
			if (aliases < MAX_ALIAS)
				alias[aliases++] = cp;
			while (*cp && !isspace(*cp))
				*cp++;
		}

		if (aliases < 2)
			continue; /* syntax error really */
		
		if (ip) {
			if (strcmp(name, alias[0]) != 0)
				continue;
		} else {
			for (i = 1; i < aliases; i++)
				if (strcasecmp(name, alias[i]) == 0)
					break;
			if (i >= aliases)
				continue;
		}

		if (inet_aton(alias[0], &in) == 0)
			break; /* bad ip address */

		addr_list[0] = &in;
		addr_list[1] = 0;
		h.h_name = alias[1];
		h.h_addrtype = AF_INET;
		h.h_length = sizeof(in);
		h.h_addr_list = (char**) addr_list;
		fclose(fp);
		return(&h);
	}
	fclose(fp);
	return((struct hostent *) NULL);
}

#else

extern struct hostent * read_etc_hosts(const char * name, int ip);

#endif


#ifdef L_read_etc_hosts
struct hostent * get_hosts_byname(const char * name)
{
	return(read_etc_hosts(name, 0));
}
#endif

#ifdef L_get_hosts_byaddr
struct hostent * get_hosts_byaddr(const char * addr, int len, int type)
{
	char	ipaddr[20];

	if (type != AF_INET || len != sizeof(struct in_addr))
		return((struct hostent *) NULL);

	strcpy(ipaddr, inet_ntoa(* (struct in_addr *) addr));
	return(read_etc_hosts(ipaddr, 1));
}
#endif

#ifdef L_if_nametoindex
unsigned int if_nametoindex(const char *ifname)
{
        errno = ENOSYS;
        return 0;
}
#endif

