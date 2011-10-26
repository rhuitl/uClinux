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

/*
 * Portions Copyright (c) 1985, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 *
 *  5-Oct-2000 W. Greathouse  wgreathouse@smva.com
 *                              Fix memory leak and memory corruption.
 *                              -- Every name resolution resulted in
 *                                 a new parse of resolv.conf and new
 *                                 copy of nameservers allocated by
 *                                 strdup.
 *                              -- Every name resolution resulted in
 *                                 a new read of resolv.conf without
 *                                 resetting index from prior read...
 *                                 resulting in exceeding array bounds.
 *
 *                              Limit nameservers read from resolv.conf
 *
 *                              Add "search" domains from resolv.conf
 *
 *                              Some systems will return a security
 *                              signature along with query answer for
 *                              dynamic DNS entries.
 *                              -- skip/ignore this answer
 *
 *                              Include arpa/nameser.h for defines.
 *
 *                              General cleanup
 *
 * 20-Jun-2001 Michal Moskal <malekith@pld.org.pl>
 *   partial IPv6 support (i.e. gethostbyname2() and resolve_address2()
 *   functions added), IPv6 nameservers are also supported.
 *
 * 6-Oct-2001 Jari Korva <jari.korva@iki.fi>
 *   more IPv6 support (IPv6 support for gethostbyaddr();
 *   address family parameter and improved IPv6 support for get_hosts_byname
 *   and read_etc_hosts; getnameinfo() port from glibc; defined
 *   defined ip6addr_any and in6addr_loopback)
 *
 * 2-Feb-2002 Erik Andersen <andersen@codepoet.org>
 *   Added gethostent(), sethostent(), and endhostent()
 *
 * 17-Aug-2002 Manuel Novoa III <mjn3@codepoet.org>
 *   Fixed __read_etc_hosts_r to return alias list, and modified buffer
 *   allocation accordingly.  See MAX_ALIASES and ALIAS_DIM below.
 *   This fixes the segfault in the Python 2.2.1 socket test.
 *
 * 04-Jan-2003 Jay Kulpinski <jskulpin@berkshire.rr.com>
 *   Fixed __decode_dotted to count the terminating null character
 *   in a host name.
 *
 * 02-Oct-2003 Tony J. White <tjw@tjw.org>
 *   Lifted dn_expand() and dependent ns_name_uncompress(), ns_name_unpack(),
 *   and ns_name_ntop() from glibc 2.3.2 for compatibility with ipsec-tools
 *   and openldap.
 *
 * 7-Sep-2004 Erik Andersen <andersen@codepoet.org>
 *   Added gethostent_r()
 *
 */

#define __FORCE_GLIBC
#include <features.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/utsname.h>
#include <sys/un.h>
#include <bits/uClibc_mutex.h>

#include <fcntl.h>

__UCLIBC_MUTEX_EXTERN(__resolv_lock);

libc_hidden_proto(memcpy)
libc_hidden_proto(memset)
libc_hidden_proto(memmove)
libc_hidden_proto(strchr)
libc_hidden_proto(strcmp)
libc_hidden_proto(strcpy)
libc_hidden_proto(strdup)
libc_hidden_proto(strlen)
libc_hidden_proto(strncat)
libc_hidden_proto(strncpy)
/* libc_hidden_proto(strnlen) */
libc_hidden_proto(strstr)
libc_hidden_proto(strcasecmp)
libc_hidden_proto(socket)
libc_hidden_proto(close)
libc_hidden_proto(fopen)
libc_hidden_proto(fclose)
libc_hidden_proto(random)
libc_hidden_proto(getservbyport)
libc_hidden_proto(getdomainname)
libc_hidden_proto(uname)
libc_hidden_proto(inet_addr)
libc_hidden_proto(inet_aton)
libc_hidden_proto(inet_pton)
libc_hidden_proto(inet_ntop)
libc_hidden_proto(connect)
libc_hidden_proto(select)
libc_hidden_proto(recv)
libc_hidden_proto(send)
libc_hidden_proto(printf)
libc_hidden_proto(sprintf)
libc_hidden_proto(snprintf)
libc_hidden_proto(fgets)
libc_hidden_proto(gethostbyname)
libc_hidden_proto(gethostbyname_r)
libc_hidden_proto(gethostbyname2_r)
libc_hidden_proto(gethostbyaddr)
libc_hidden_proto(gethostbyaddr_r)
libc_hidden_proto(ns_name_uncompress)
libc_hidden_proto(ns_name_unpack)
libc_hidden_proto(ns_name_ntop)
libc_hidden_proto(res_init)
libc_hidden_proto(res_query)
libc_hidden_proto(res_querydomain)
libc_hidden_proto(gethostent_r)
libc_hidden_proto(fprintf)
libc_hidden_proto(__h_errno_location)
#ifdef __UCLIBC_HAS_XLOCALE__
libc_hidden_proto(__ctype_b_loc)
#elif __UCLIBC_HAS_CTYPE_TABLES__
libc_hidden_proto(__ctype_b)
#endif



#define MAX_RECURSE 5
#define REPLY_TIMEOUT 10
#define MAX_RETRIES 3
#define MAX_SERVERS 3
#define MAX_SEARCH 4

#define MAX_ALIASES	5

/* 1:ip + 1:full + MAX_ALIASES:aliases + 1:NULL */
#define ALIAS_DIM		(2 + MAX_ALIASES + 1)

#undef DEBUG
/* #define DEBUG */

#ifdef DEBUG
#define DPRINTF(X,args...) fprintf(stderr, X, ##args)
#else
#define DPRINTF(X,args...)
#endif /* DEBUG */


/* Global stuff (stuff needing to be locked to be thread safe)... */
extern int __nameservers attribute_hidden;
extern char * __nameserver[MAX_SERVERS] attribute_hidden;
extern int __searchdomains attribute_hidden;
extern char * __searchdomain[MAX_SEARCH] attribute_hidden;





/* Structs */
struct resolv_header {
	int id;
	int qr,opcode,aa,tc,rd,ra,rcode;
	int qdcount;
	int ancount;
	int nscount;
	int arcount;
};

struct resolv_question {
	char * dotted;
	int qtype;
	int qclass;
};

struct resolv_answer {
	char * dotted;
	int atype;
	int aclass;
	int ttl;
	int rdlength;
	const unsigned char * rdata;
	int rdoffset;
	char* buf;
	size_t buflen;
	size_t add_count;
};

enum etc_hosts_action {
    GET_HOSTS_BYNAME = 0,
    GETHOSTENT,
    GET_HOSTS_BYADDR,
};

/* function prototypes */
extern int __get_hosts_byname_r(const char * name, int type,
			      struct hostent * result_buf,
			      char * buf, size_t buflen,
			      struct hostent ** result,
			      int * h_errnop) attribute_hidden;
extern int __get_hosts_byaddr_r(const char * addr, int len, int type,
			      struct hostent * result_buf,
			      char * buf, size_t buflen,
			      struct hostent ** result,
			      int * h_errnop) attribute_hidden;
extern void __open_etc_hosts(FILE **fp) attribute_hidden;
extern int __read_etc_hosts_r(FILE *fp, const char * name, int type,
			    enum etc_hosts_action action,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop) attribute_hidden;
extern int __dns_lookup(const char * name, int type, int nscount,
	char ** nsip, unsigned char ** outpacket, struct resolv_answer * a) attribute_hidden;

extern int __encode_dotted(const char * dotted, unsigned char * dest, int maxlen) attribute_hidden;
extern int __decode_dotted(const unsigned char * const message, int offset,
	char * dest, int maxlen) attribute_hidden;
extern int __length_dotted(const unsigned char * const message, int offset) attribute_hidden;
extern int __encode_header(struct resolv_header * h, unsigned char * dest, int maxlen) attribute_hidden;
extern int __decode_header(unsigned char * data, struct resolv_header * h) attribute_hidden;
extern int __encode_question(const struct resolv_question * const q,
	unsigned char * dest, int maxlen) attribute_hidden;
extern int __decode_question(const unsigned char * const message, int offset,
	struct resolv_question * q) attribute_hidden;
extern int __encode_answer(struct resolv_answer * a,
	unsigned char * dest, int maxlen) attribute_hidden;
extern int __decode_answer(const unsigned char * message, int offset,
	struct resolv_answer * a) attribute_hidden;
extern int __length_question(const unsigned char * const message, int offset) attribute_hidden;
extern void __open_nameservers(void) attribute_hidden;
extern void __close_nameservers(void) attribute_hidden;
extern int __dn_expand(const u_char *, const u_char *, const u_char *,
	char *, int);

#ifdef L_encodeh
int attribute_hidden __encode_header(struct resolv_header *h, unsigned char *dest, int maxlen)
{
	if (maxlen < HFIXEDSZ)
		return -1;

	dest[0] = (h->id & 0xff00) >> 8;
	dest[1] = (h->id & 0x00ff) >> 0;
	dest[2] = (h->qr ? 0x80 : 0) |
		((h->opcode & 0x0f) << 3) |
		(h->aa ? 0x04 : 0) |
		(h->tc ? 0x02 : 0) |
		(h->rd ? 0x01 : 0);
	dest[3] = (h->ra ? 0x80 : 0) | (h->rcode & 0x0f);
	dest[4] = (h->qdcount & 0xff00) >> 8;
	dest[5] = (h->qdcount & 0x00ff) >> 0;
	dest[6] = (h->ancount & 0xff00) >> 8;
	dest[7] = (h->ancount & 0x00ff) >> 0;
	dest[8] = (h->nscount & 0xff00) >> 8;
	dest[9] = (h->nscount & 0x00ff) >> 0;
	dest[10] = (h->arcount & 0xff00) >> 8;
	dest[11] = (h->arcount & 0x00ff) >> 0;

	return HFIXEDSZ;
}
#endif

#ifdef L_decodeh
int attribute_hidden __decode_header(unsigned char *data, struct resolv_header *h)
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

	return HFIXEDSZ;
}
#endif

#ifdef L_encoded
/* Encode a dotted string into nameserver transport-level encoding.
   This routine is fairly dumb, and doesn't attempt to compress
   the data */

int attribute_hidden __encode_dotted(const char *dotted, unsigned char *dest, int maxlen)
{
	unsigned used = 0;

	while (dotted && *dotted) {
		char *c = strchr(dotted, '.');
		int l = c ? c - dotted : strlen(dotted);

		if (l >= (maxlen - used - 1))
			return -1;

		dest[used++] = l;
		memcpy(dest + used, dotted, l);
		used += l;

		if (c)
			dotted = c + 1;
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

int attribute_hidden __decode_dotted(const unsigned char * const data, int offset,
				  char *dest, int maxlen)
{
	int l;
	bool measure = 1;
	unsigned total = 0;
	unsigned used = 0;

	if (!data)
		return -1;

	while ((l=data[offset++])) {
		if (measure)
		    total++;
		if ((l & 0xc0) == (0xc0)) {
			if (measure)
				total++;
			/* compressed item, redirect */
			offset = ((l & 0x3f) << 8) | data[offset];
			measure = 0;
			continue;
		}

		if ((used + l + 1) >= maxlen)
			return -1;

		memcpy(dest + used, data + offset, l);
		offset += l;
		used += l;
		if (measure)
			total += l;

		if (data[offset] != 0)
			dest[used++] = '.';
		else
			dest[used++] = '\0';
	}

	/* The null byte must be counted too */
	if (measure) {
	    total++;
	}

	DPRINTF("Total decode len = %d\n", total);

	return total;
}
#endif

#ifdef L_lengthd
int attribute_hidden __length_dotted(const unsigned char * const data, int offset)
{
	int orig_offset = offset;
	int l;

	if (!data)
		return -1;

	while ((l = data[offset++])) {

		if ((l & 0xc0) == (0xc0)) {
			offset++;
			break;
		}

		offset += l;
	}

	return offset - orig_offset;
}
#endif

#ifdef L_encodeq
int attribute_hidden __encode_question(const struct resolv_question * const q,
					unsigned char *dest, int maxlen)
{
	int i;

	i = __encode_dotted(q->dotted, dest, maxlen);
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

	return i + 4;
}
#endif

#ifdef L_decodeq
int attribute_hidden __decode_question(const unsigned char * const message, int offset,
					struct resolv_question *q)
{
	char temp[256];
	int i;

	i = __decode_dotted(message, offset, temp, sizeof(temp));
	if (i < 0)
		return i;

	offset += i;

	q->dotted = strdup(temp);
	q->qtype = (message[offset + 0] << 8) | message[offset + 1];
	q->qclass = (message[offset + 2] << 8) | message[offset + 3];

	return i + 4;
}
#endif

#ifdef L_lengthq
int attribute_hidden __length_question(const unsigned char * const message, int offset)
{
	int i;

	i = __length_dotted(message, offset);
	if (i < 0)
		return i;

	return i + 4;
}
#endif

#ifdef L_encodea
int attribute_hidden __encode_answer(struct resolv_answer *a, unsigned char *dest, int maxlen)
{
	int i;

	i = __encode_dotted(a->dotted, dest, maxlen);
	if (i < 0)
		return i;

	dest += i;
	maxlen -= i;

	if (maxlen < (RRFIXEDSZ+a->rdlength))
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

	return i + RRFIXEDSZ + a->rdlength;
}
#endif

#ifdef L_decodea
int attribute_hidden __decode_answer(const unsigned char *message, int offset,
				  struct resolv_answer *a)
{
	char temp[256];
	int i;

	i = __decode_dotted(message, offset, temp, sizeof(temp));
	if (i < 0)
		return i;

	message += offset + i;

	a->dotted = strdup(temp);
	a->atype = (message[0] << 8) | message[1];
	message += 2;
	a->aclass = (message[0] << 8) | message[1];
	message += 2;
	a->ttl = (message[0] << 24) |
		(message[1] << 16) | (message[2] << 8) | (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1];
	message += 2;
	a->rdata = message;
	a->rdoffset = offset + i + RRFIXEDSZ;

	DPRINTF("i=%d,rdlength=%d\n", i, a->rdlength);

	return i + RRFIXEDSZ + a->rdlength;
}
#endif

#ifdef L_encodep
int __encode_packet(struct resolv_header *h,
	struct resolv_question **q,
	struct resolv_answer **an,
	struct resolv_answer **ns,
	struct resolv_answer **ar,
	unsigned char *dest, int maxlen) attribute_hidden;
int __encode_packet(struct resolv_header *h,
					struct resolv_question **q,
					struct resolv_answer **an,
					struct resolv_answer **ns,
					struct resolv_answer **ar,
					unsigned char *dest, int maxlen)
{
	int i, total = 0;
	unsigned j;

	i = __encode_header(h, dest, maxlen);
	if (i < 0)
		return i;

	dest += i;
	maxlen -= i;
	total += i;

	for (j = 0; j < h->qdcount; j++) {
		i = __encode_question(q[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}

	for (j = 0; j < h->ancount; j++) {
		i = __encode_answer(an[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	for (j = 0; j < h->nscount; j++) {
		i = __encode_answer(ns[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	for (j = 0; j < h->arcount; j++) {
		i = __encode_answer(ar[j], dest, maxlen);
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
int __decode_packet(unsigned char *data, struct resolv_header *h) attribute_hidden;
int __decode_packet(unsigned char *data, struct resolv_header *h)
{
	return __decode_header(data, h);
}
#endif

#ifdef L_formquery
int __form_query(int id, const char *name, int type, unsigned char *packet, int maxlen);
int __form_query(int id, const char *name, int type, unsigned char *packet,
				 int maxlen)
{
	struct resolv_header h;
	struct resolv_question q;
	int i, j;

	memset(&h, 0, sizeof(h));
	h.id = id;
	h.qdcount = 1;

	q.dotted = (char *) name;
	q.qtype = type;
	q.qclass = C_IN; /* CLASS_IN */

	i = __encode_header(&h, packet, maxlen);
	if (i < 0)
		return i;

	j = __encode_question(&q, packet + i, maxlen - i);
	if (j < 0)
		return j;

	return i + j;
}
#endif

#ifdef L_dnslookup
__UCLIBC_MUTEX_STATIC(mylock, PTHREAD_MUTEX_INITIALIZER);

/* SURF random number generator -
   The SURF random number generator was taken from djbdns-1.05, by 
   Daniel J Berstein, which is public domain. */

static u_int32_t seed[32];
static u_int32_t in[12];
static u_int32_t out[8];

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  u_int32_t t[12]; u_int32_t x; u_int32_t sum = 0;
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

/* Just for the record, having to lock __dns_lookup() just for these two globals
 * is pretty lame.  I think these two variables can probably be de-global-ized,
 * which should eliminate the need for doing locking here...  Needs a closer
 * look anyways. */
static int ns=0;

int attribute_hidden __dns_lookup(const char *name, int type, int nscount, char **nsip,
			   unsigned char **outpacket, struct resolv_answer *a)
{
	int i, j, len, fd, pos, rc;
	struct timeval tv;
	fd_set fds;
	struct resolv_header h;
	struct resolv_question q;
	struct resolv_answer ma;
	bool first_answer = 1;
	unsigned retries = 0;
	unsigned char * packet = malloc(PACKETSZ);
	char *dns, *lookup = malloc(MAXDNAME);
	int variant = -1;
	struct sockaddr_in sa;
	int local_ns = -1, local_id = -1;
#ifdef __UCLIBC_HAS_IPV6__
	bool v6;
	struct sockaddr_in6 sa6;
#endif
	static int init_rand = 0;

	fd = -1;

	if (!packet || !lookup || !nscount)
	    goto fail;

	DPRINTF("Looking up type %d answer for '%s'\n", type, name);

	/* Mess with globals while under lock */
	__UCLIBC_MUTEX_LOCK(mylock);
	local_ns = ns % nscount;
	__UCLIBC_MUTEX_UNLOCK(mylock);

	if (!init_rand) {
		struct timeval tv;
		int fd;
		int fail = 0;

		/* Just seed the RNG once only per process, even if we can't get a good source */
		init_rand = 1;

		__UCLIBC_MUTEX_LOCK(mylock);
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
			/* Failure reading urandom - just try our best to get some randomness */
			u_int32_t r;
			gettimeofday(&tv, NULL);
			r = (tv.tv_usec << 16) ^ tv.tv_sec ^ getpid();
			srand(r);

			for (i = 0; i < sizeof(seed) / 4; i++) {
				r = random();
				memcpy(&seed[i], &r, sizeof(u_int32_t));
			}
			for (i = 0; i < sizeof(in) / 4; i++) {
				r = random();
				memcpy(&in[i], &r, sizeof(u_int32_t));
			}
		}
		__UCLIBC_MUTEX_UNLOCK(mylock);
	}

	while (retries < MAX_RETRIES) {
		if (fd != -1)
			close(fd);

		memset(packet, 0, PACKETSZ);

		memset(&h, 0, sizeof(h));

		local_id = dns_rand16();
		h.id = local_id;
		__UCLIBC_MUTEX_LOCK(__resolv_lock);
		/* this is really __nameserver[] which is a global that
		   needs to hold __resolv_lock before access!! */
		dns = nsip[local_ns];
		__UCLIBC_MUTEX_UNLOCK(__resolv_lock);

		h.qdcount = 1;
		h.rd = 1;

		DPRINTF("encoding header\n", h.rd);

		i = __encode_header(&h, packet, PACKETSZ);
		if (i < 0)
			goto fail;

		strncpy(lookup,name,MAXDNAME);
		if (variant >= 0) {
			__UCLIBC_MUTEX_LOCK(__resolv_lock);
			if (variant < __searchdomains) {
				strncat(lookup,".", MAXDNAME);
				strncat(lookup,__searchdomain[variant], MAXDNAME);
			}
			__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
		}
		DPRINTF("lookup name: %s\n", lookup);
		q.dotted = (char *)lookup;
		q.qtype = type;
		q.qclass = C_IN; /* CLASS_IN */

		j = __encode_question(&q, packet+i, PACKETSZ-i);
		if (j < 0)
			goto fail;

		len = i + j;

		DPRINTF("On try %d, sending query to port %d of machine %s\n",
				retries+1, NAMESERVER_PORT, dns);

#ifdef __UCLIBC_HAS_IPV6__
		__UCLIBC_MUTEX_LOCK(__resolv_lock);
		/* 'dns' is really __nameserver[] which is a global that
		   needs to hold __resolv_lock before access!! */
		v6 = inet_pton(AF_INET6, dns, &sa6.sin6_addr) > 0;
		__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
		fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
		if (fd < 0) {
			retries++;
		    continue;
		}

		/* Connect to the UDP socket so that asyncronous errors are returned */
#ifdef __UCLIBC_HAS_IPV6__
		if (v6) {
		    sa6.sin6_family = AF_INET6;
		    sa6.sin6_port = htons(NAMESERVER_PORT);
		    /* sa6.sin6_addr is already here */
		    rc = connect(fd, (struct sockaddr *) &sa6, sizeof(sa6));
		} else {
#endif
		    sa.sin_family = AF_INET;
		    sa.sin_port = htons(NAMESERVER_PORT);
		    __UCLIBC_MUTEX_LOCK(__resolv_lock);
		    /* 'dns' is really __nameserver[] which is a global that
		       needs to hold __resolv_lock before access!! */
		    sa.sin_addr.s_addr = inet_addr(dns);
		    __UCLIBC_MUTEX_UNLOCK(__resolv_lock);
		    rc = connect(fd, (struct sockaddr *) &sa, sizeof(sa));
#ifdef __UCLIBC_HAS_IPV6__
		}
#endif
		if (rc < 0) {
		    if (errno == ENETUNREACH) {
				/* routing error, presume not transient */
				goto tryall;
		    } else
				/* retry */
				retries++;
			continue;
		}

		DPRINTF("Transmitting packet of length %d, id=%d, qr=%d\n",
				len, h.id, h.qr);

		send(fd, packet, len, 0);

		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		tv.tv_sec = REPLY_TIMEOUT;
		tv.tv_usec = 0;
		if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
		    DPRINTF("Timeout\n");

			/* timed out, so retry send and receive,
			 * to next nameserver on queue */
			goto tryall;
		}

		len = recv(fd, packet, 512, 0);
		if (len < HFIXEDSZ) {
			/* too short ! */
			goto again;
		}

		__decode_header(packet, &h);

		DPRINTF("id = %d, qr = %d\n", h.id, h.qr);

		if ((h.id != local_id) || (!h.qr)) {
			/* unsolicited */
			goto again;
		}


		DPRINTF("Got response %s\n", "(i think)!");
		DPRINTF("qrcount=%d,ancount=%d,nscount=%d,arcount=%d\n",
				h.qdcount, h.ancount, h.nscount, h.arcount);
		DPRINTF("opcode=%d,aa=%d,tc=%d,rd=%d,ra=%d,rcode=%d\n",
				h.opcode, h.aa, h.tc, h.rd, h.ra, h.rcode);

		if ((h.rcode) || (h.ancount < 1)) {
			/* negative result, not present */
			goto again;
		}

		pos = HFIXEDSZ;

		for (j = 0; j < h.qdcount; j++) {
			DPRINTF("Skipping question %d at %d\n", j, pos);
			i = __length_question(packet, pos);
			DPRINTF("Length of question %d is %d\n", j, i);
			if (i < 0)
				goto again;
			pos += i;
		}
		DPRINTF("Decoding answer at pos %d\n", pos);

		first_answer = 1;
		for (j=0;j<h.ancount;j++,pos += i)
			{
				i = __decode_answer(packet, pos, &ma);

				if (i<0) {
					DPRINTF("failed decode %d\n", i);
					goto again;
				}

				if ( first_answer )
					{
						ma.buf = a->buf;
						ma.buflen = a->buflen;
						ma.add_count = a->add_count;
						memcpy(a, &ma, sizeof(ma));
						if (a->atype != T_SIG && (0 == a->buf || (type != T_A && type != T_AAAA)))
							{
								break;
							}
						if (a->atype != type)
							{
								free(a->dotted);
								continue;
							}
						a->add_count = h.ancount - j - 1;
						if ((a->rdlength + sizeof(struct in_addr*)) * a->add_count > a->buflen)
							{
								break;
							}
						a->add_count = 0;
						first_answer = 0;
					}
				else
					{
						free(ma.dotted);
						if (ma.atype != type)
							{
								continue;
							}
						if (a->rdlength != ma.rdlength)
							{
								free(a->dotted);
								DPRINTF("Answer address len(%u) differs from original(%u)\n",
										ma.rdlength, a->rdlength);
								goto again;
							}
						memcpy(a->buf + (a->add_count * ma.rdlength), ma.rdata, ma.rdlength);
						++a->add_count;
					}
			}

		DPRINTF("Answer name = |%s|\n", a->dotted);
		DPRINTF("Answer type = |%d|\n", a->atype);

		close(fd);

		if (outpacket)
			*outpacket = packet;
		else
			free(packet);
		free(lookup);

		/* Mess with globals while under lock */
		__UCLIBC_MUTEX_LOCK(mylock);
		ns = local_ns;
		__UCLIBC_MUTEX_UNLOCK(mylock);

		return (len);				/* success! */

	tryall:
		/* if there are other nameservers, give them a go,
		   otherwise return with error */
		{
		    variant = -1;
			local_ns = (local_ns + 1) % nscount;
			if (local_ns == 0)
				retries++;

			continue;
		}

	again:
		/* if there are searchdomains, try them or fallback as passed */
		{
		    int sdomains;
		    __UCLIBC_MUTEX_LOCK(__resolv_lock);
		    sdomains=__searchdomains;
		    __UCLIBC_MUTEX_UNLOCK(__resolv_lock);

		    if (variant < sdomains - 1) {
				/* next search */
				variant++;
		    } else {
				/* next server, first search */
				local_ns = (local_ns + 1) % nscount;
				if (local_ns == 0)
					retries++;

				variant = -1;
		    }
		}
	}

 fail:
	if (fd != -1)
	    close(fd);
	if (lookup)
	    free(lookup);
	if (packet)
	    free(packet);
	h_errno = NETDB_INTERNAL;
	/* Mess with globals while under lock */
	if (local_ns != -1) {
	    __UCLIBC_MUTEX_LOCK(mylock);
	    ns = local_ns;
	    __UCLIBC_MUTEX_UNLOCK(mylock);
	}
	return -1;
}
#endif

#ifdef L_opennameservers

/* We use __resolv_lock to guard access to the
 * '__nameservers' and __searchdomains globals */
int __nameservers;
char * __nameserver[MAX_SERVERS];
int __searchdomains;
char * __searchdomain[MAX_SEARCH];

__UCLIBC_MUTEX_INIT(__resolv_lock, PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP);

/*
 *	we currently read formats not quite the same as that on normal
 *	unix systems, we can have a list of nameservers after the keyword.
 */

void attribute_hidden __open_nameservers()
{
	FILE *fp;
	int i;
#define RESOLV_ARGS 5
	char szBuffer[128], *p, *argv[RESOLV_ARGS];
	int argc;
	/* int rv = 0; */

	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	if (__nameservers > 0) {
		goto DONE;
	}

	if ((fp = fopen("/etc/resolv.conf", "r")) ||
		(fp = fopen("/etc/config/resolv.conf", "r")))
		{

			while (fgets(szBuffer, sizeof(szBuffer), fp) != NULL) {

				for (p = szBuffer; *p && isspace(*p); p++)
					/* skip white space */;
				if (*p == '\0' || *p == '\n' || *p == '#') /* skip comments etc */
					continue;
				argc = 0;
				while (*p && argc < RESOLV_ARGS) {
					argv[argc++] = p;
					while (*p && !isspace(*p) && *p != '\n')
						p++;
					while (*p && (isspace(*p) || *p == '\n')) /* remove spaces */
						*p++ = '\0';
				}

				if (strcmp(argv[0], "nameserver") == 0) {
					for (i = 1; i < argc && __nameservers < MAX_SERVERS; i++) {
						__nameserver[__nameservers++] = strdup(argv[i]);
						DPRINTF("adding nameserver %s\n", argv[i]);
					}
				}

				/* domain and search are mutually exclusive, the last one wins */
				if (strcmp(argv[0],"domain")==0 || strcmp(argv[0],"search")==0) {
					while (__searchdomains > 0) {
						free(__searchdomain[--__searchdomains]);
						__searchdomain[__searchdomains] = NULL;
					}
					for (i=1; i < argc && __searchdomains < MAX_SEARCH; i++) {
						__searchdomain[__searchdomains++] = strdup(argv[i]);
						DPRINTF("adding search %s\n", argv[i]);
					}
				}
			}
			fclose(fp);
			DPRINTF("nameservers = %d\n", __nameservers);
			goto DONE;
		}
	DPRINTF("failed to open %s\n", "resolv.conf");
	h_errno = NO_RECOVERY;

	/* rv = -1; */

 DONE:
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	/* return rv; */
}
#endif


#ifdef L_closenameservers

void attribute_hidden __close_nameservers(void)
{
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	while (__nameservers > 0) {
		free(__nameserver[--__nameservers]);
		__nameserver[__nameservers] = NULL;
	}
	while (__searchdomains > 0) {
		free(__searchdomain[--__searchdomains]);
		__searchdomain[__searchdomains] = NULL;
	}
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
}
#endif

#ifdef L_gethostbyname

struct hostent *gethostbyname(const char *name)
{
	static struct hostent h;
	static char buf[sizeof(struct in_addr) +
					sizeof(struct in_addr *)*2 +
					sizeof(char *)*(ALIAS_DIM) + 384/*namebuffer*/ + 32/* margin */];
	struct hostent *hp;

	gethostbyname_r(name, &h, buf, sizeof(buf), &hp, &h_errno);

	return hp;
}
libc_hidden_def(gethostbyname)
#endif

#ifdef L_gethostbyname2

struct hostent *gethostbyname2(const char *name, int family)
{
#ifndef __UCLIBC_HAS_IPV6__
	return family == AF_INET ? gethostbyname(name) : (struct hostent*)0;
#else /* __UCLIBC_HAS_IPV6__ */
	static struct hostent h;
	static char buf[sizeof(struct in6_addr) +
					sizeof(struct in6_addr *)*2 +
					sizeof(char *)*(ALIAS_DIM) + 384/*namebuffer*/ + 32/* margin */];
	struct hostent *hp;

	gethostbyname2_r(name, family, &h, buf, sizeof(buf), &hp, &h_errno);

	return hp;
#endif /* __UCLIBC_HAS_IPV6__ */
}
#endif



#ifdef L_res_init
/* We use __resolv_lock to guard access to global '_res' */
struct __res_state _res;

int res_init(void)
{
	struct __res_state *rp = &(_res);

	__UCLIBC_MUTEX_LOCK(__resolv_lock);	/* must be a recursive lock! */
	__close_nameservers();
	__open_nameservers();
	rp->retrans = RES_TIMEOUT;
	rp->retry = 4;
	rp->options = RES_INIT;
	rp->id = (u_int) random();
	rp->nsaddr.sin_addr.s_addr = INADDR_ANY;
	rp->nsaddr.sin_family = AF_INET;
	rp->nsaddr.sin_port = htons(NAMESERVER_PORT);
	rp->ndots = 1;
	/** rp->pfcode = 0; **/
	rp->_vcsock = -1;
	/** rp->_flags = 0; **/
	/** rp->qhook = NULL; **/
	/** rp->rhook = NULL; **/
	/** rp->_u._ext.nsinit = 0; **/

	if(__searchdomains) {
		int i;
		for(i=0; i<__searchdomains; i++) {
			rp->dnsrch[i] = __searchdomain[i];
		}
	}

	if(__nameservers) {
		int i;
		struct in_addr a;
		for(i=0; i<__nameservers; i++) {
			if (inet_aton(__nameserver[i], &a)) {
				rp->nsaddr_list[i].sin_addr = a;
				rp->nsaddr_list[i].sin_family = AF_INET;
				rp->nsaddr_list[i].sin_port = htons(NAMESERVER_PORT);
			}
		}
	}
	rp->nscount = __nameservers;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);

	return(0);
}
libc_hidden_def(res_init)

#ifdef __UCLIBC_HAS_BSD_RES_CLOSE__
void res_close( void )
{
	__close_nameservers();
	memset(&_res, 0, sizeof(_res));
}
#endif

#endif


#ifdef L_res_query

#ifndef MIN
#define MIN(x, y)	((x) < (y) ? (x) : (y))
#endif

int res_query(const char *dname, int class, int type,
              unsigned char *answer, int anslen)
{
	int i;
	unsigned char * packet = 0;
	struct resolv_answer a;
	int __nameserversXX;
	char ** __nameserverXX;

	__open_nameservers();
	if (!dname || class != 1 /* CLASS_IN */) {
		h_errno = NO_RECOVERY;
		return(-1);
	}

	memset((char *) &a, '\0', sizeof(a));

	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	__nameserversXX=__nameservers;
	__nameserverXX=__nameserver;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	i = __dns_lookup(dname, type, __nameserversXX, __nameserverXX, &packet, &a);

	if (i < 0) {
		h_errno = TRY_AGAIN;
		return(-1);
	}

	free(a.dotted);

	if (a.atype == type) { /* CNAME*/
		int len = MIN(anslen, i);
		memcpy(answer, packet, len);
		if (packet)
			free(packet);
		return(len);
	}
	if (packet)
		free(packet);
	return i;
}
libc_hidden_def(res_query)

/*
 * Formulate a normal query, send, and retrieve answer in supplied buffer.
 * Return the size of the response on success, -1 on error.
 * If enabled, implement search rules until answer or unrecoverable failure
 * is detected.  Error code, if any, is left in h_errno.
 */
#define __TRAILING_DOT	(1<<0)
#define __GOT_NODATA	(1<<1)
#define __GOT_SERVFAIL	(1<<2)
#define __TRIED_AS_IS	(1<<3)
int res_search(name, class, type, answer, anslen)
	 const char *name;	/* domain name */
	 int class, type;	/* class and type of query */
	 u_char *answer;		/* buffer to put answer */
	 int anslen;		/* size of answer */
{
	const char *cp, * const *domain;
	HEADER *hp = (HEADER *)(void *)answer;
	u_int dots;
	unsigned _state = 0;
	int ret, saved_herrno;
	u_long _res_options;
	unsigned _res_ndots;
	char **_res_dnsrch;

	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if ((!name || !answer) || ((_res_options & RES_INIT) == 0 && res_init() == -1)) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

	errno = 0;
	h_errno = HOST_NOT_FOUND;	/* default, if we never query */
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');

	if (cp > name && *--cp == '.')
		_state |= __TRAILING_DOT;

	/*
	 * If there are dots in the name already, let's just give it a try
	 * 'as is'.  The threshold can be set with the "ndots" option.
	 */
	saved_herrno = -1;
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_ndots = _res.ndots;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if (dots >= _res_ndots) {
		ret = res_querydomain(name, NULL, class, type, answer, anslen);
		if (ret > 0)
			return (ret);
		saved_herrno = h_errno;
		_state |= __TRIED_AS_IS;
	}

	/*
	 * We do at least one level of search if
	 *	- there is no dot and RES_DEFNAME is set, or
	 *	- there is at least one dot, there is no trailing dot,
	 *	  and RES_DNSRCH is set.
	 */
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	_res_dnsrch = _res.dnsrch;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if ((!dots && (_res_options & RES_DEFNAMES)) ||
	    (dots && !(_state & __TRAILING_DOT) && (_res_options & RES_DNSRCH))) {
		bool done = 0;

		for (domain = (const char * const *)_res_dnsrch;
			 *domain && !done;
			 domain++) {

			ret = res_querydomain(name, *domain, class, type,
								  answer, anslen);
			if (ret > 0)
				return (ret);

			/*
			 * If no server present, give up.
			 * If name isn't found in this domain,
			 * keep trying higher domains in the search list
			 * (if that's enabled).
			 * On a NO_DATA error, keep trying, otherwise
			 * a wildcard entry of another type could keep us
			 * from finding this entry higher in the domain.
			 * If we get some other error (negative answer or
			 * server failure), then stop searching up,
			 * but try the input name below in case it's
			 * fully-qualified.
			 */
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return (-1);
			}

			switch (h_errno) {
				case NO_DATA:
					_state |= __GOT_NODATA;
					/* FALLTHROUGH */
				case HOST_NOT_FOUND:
					/* keep trying */
					break;
				case TRY_AGAIN:
					if (hp->rcode == SERVFAIL) {
						/* try next search element, if any */
						_state |= __GOT_SERVFAIL;
						break;
					}
					/* FALLTHROUGH */
				default:
					/* anything else implies that we're done */
					done = 1;
			}
			/*
			 * if we got here for some reason other than DNSRCH,
			 * we only wanted one iteration of the loop, so stop.
			 */
			__UCLIBC_MUTEX_LOCK(__resolv_lock);
			_res_options = _res.options;
			__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
			if (!(_res_options & RES_DNSRCH))
				done = 1;
		}
	}

	/*
	 * if we have not already tried the name "as is", do that now.
	 * note that we do this regardless of how many dots were in the
	 * name or whether it ends with a dot.
	 */
	if (!(_state & __TRIED_AS_IS)) {
		ret = res_querydomain(name, NULL, class, type, answer, anslen);
		if (ret > 0)
			return (ret);
	}

	/*
	 * if we got here, we didn't satisfy the search.
	 * if we did an initial full query, return that query's h_errno
	 * (note that we wouldn't be here if that query had succeeded).
	 * else if we ever got a nodata, send that back as the reason.
	 * else send back meaningless h_errno, that being the one from
	 * the last DNSRCH we did.
	 */
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (_state & __GOT_NODATA)
		h_errno = NO_DATA;
	else if (_state & __GOT_SERVFAIL)
		h_errno = TRY_AGAIN;
	return (-1);
}
#undef __TRAILING_DOT
#undef __GOT_NODATA
#undef __GOT_SERVFAIL
#undef __TRIED_AS_IS
/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
int res_querydomain(name, domain, class, type, answer, anslen)
	 const char *name, *domain;
	 int class, type;	/* class and type of query */
	 u_char *answer;		/* buffer to put answer */
	 int anslen;		/* size of answer */
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;
	u_long _res_options;

	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if ((!name || !answer) || ((_res_options & RES_INIT) == 0 && res_init() == -1)) {
		h_errno = NETDB_INTERNAL;
		return (-1);
	}

#ifdef DEBUG
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if (_res_options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s, %d, %d)\n",
			   name, domain?domain:"<Nil>", class, type);
#endif
	if (domain == NULL) {
		/*
		 * Check for trailing '.';
		 * copy without '.' if present.
		 */
		n = strlen(name);
		if (n + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + 1 + d + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return (-1);
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return (res_query(longname, class, type, answer, anslen));
}
libc_hidden_def(res_querydomain)

/* res_mkquery */
/* res_send */
/* dn_comp */
/* dn_expand */
#endif

#ifdef L_gethostbyaddr
struct hostent *gethostbyaddr (const void *addr, socklen_t len, int type)
{
	static struct hostent h;
	static char buf[
#ifndef __UCLIBC_HAS_IPV6__
					sizeof(struct in_addr) + sizeof(struct in_addr *)*2 +
#else
					sizeof(struct in6_addr) + sizeof(struct in6_addr *)*2 +
#endif /* __UCLIBC_HAS_IPV6__ */
					sizeof(char *)*(ALIAS_DIM) + 384/*namebuffer*/ + 32/* margin */];
	struct hostent *hp;

	gethostbyaddr_r(addr, len, type, &h, buf, sizeof(buf), &hp, &h_errno);

	return hp;
}
libc_hidden_def(gethostbyaddr)
#endif


#ifdef L_read_etc_hosts_r

void attribute_hidden __open_etc_hosts(FILE **fp)
{
	if ((*fp = fopen("/etc/hosts", "r")) == NULL) {
		*fp = fopen("/etc/config/hosts", "r");
	}
	return;
}

int attribute_hidden __read_etc_hosts_r(FILE * fp, const char * name, int type,
		     enum etc_hosts_action action,
		     struct hostent * result_buf,
		     char * buf, size_t buflen,
		     struct hostent ** result,
		     int * h_errnop)
{
	struct in_addr	*in=NULL;
	struct in_addr	**addr_list=NULL;
#ifdef __UCLIBC_HAS_IPV6__
	struct in6_addr	*in6=NULL;
	struct in6_addr	**addr_list6=NULL;
#endif /* __UCLIBC_HAS_IPV6__ */
	char *cp, **alias;
	int aliases, i, ret=HOST_NOT_FOUND;

	if (buflen < sizeof(char *)*(ALIAS_DIM))
		return ERANGE;
	alias=(char **)buf;
	buf+=sizeof(char **)*(ALIAS_DIM);
	buflen-=sizeof(char **)*(ALIAS_DIM);

	if (action!=GETHOSTENT) {
#ifdef __UCLIBC_HAS_IPV6__
		char *p=buf;
		size_t len=buflen;
#endif /* __UCLIBC_HAS_IPV6__ */
		*h_errnop=NETDB_INTERNAL;
		if (buflen < sizeof(*in))
			return ERANGE;
		in=(struct in_addr*)buf;
		buf+=sizeof(*in);
		buflen-=sizeof(*in);

		if (buflen < sizeof(*addr_list)*2)
			return ERANGE;
		addr_list=(struct in_addr **)buf;
		buf+=sizeof(*addr_list)*2;
		buflen-=sizeof(*addr_list)*2;

#ifdef __UCLIBC_HAS_IPV6__
		if (len < sizeof(*in6))
			return ERANGE;
		in6=(struct in6_addr*)p;
		p+=sizeof(*in6);
		len-=sizeof(*in6);

		if (len < sizeof(*addr_list6)*2)
			return ERANGE;
		addr_list6=(struct in6_addr**)p;
		p+=sizeof(*addr_list6)*2;
		len-=sizeof(*addr_list6)*2;

		if (len < buflen) {
			buflen=len;
			buf=p;
		}
#endif /* __UCLIBC_HAS_IPV6__ */

		if (buflen < 80)
			return ERANGE;

		__open_etc_hosts(&fp);
		if (fp == NULL) {
			result=NULL;
			return errno;
		}
	}

	*h_errnop=HOST_NOT_FOUND;
	while (fgets(buf, buflen, fp)) {
		if ((cp = strchr(buf, '#')))
			*cp = '\0';
		DPRINTF("Looking at: %s\n", buf);
		aliases = 0;

		cp = buf;
		while (*cp) {
			while (*cp && isspace(*cp))
				*cp++ = '\0';
			if (!*cp)
				continue;
			if (aliases < (2+MAX_ALIASES))
				alias[aliases++] = cp;
			while (*cp && !isspace(*cp))
				cp++;
		}
		alias[aliases] = 0;

		if (aliases < 2)
			continue; /* syntax error really */

		if (action==GETHOSTENT) {
			/* Return whatever the next entry happens to be. */
			break;
		} else if (action==GET_HOSTS_BYADDR) {
			if (strcmp(name, alias[0]) != 0)
				continue;
		} else {
			/* GET_HOSTS_BYNAME */
			for (i = 1; i < aliases; i++)
				if (strcasecmp(name, alias[i]) == 0)
					break;
			if (i >= aliases)
				continue;
		}

		if (type == AF_INET && inet_pton(AF_INET, alias[0], in) > 0) {
			DPRINTF("Found INET\n");
			addr_list[0] = in;
			addr_list[1] = 0;
			result_buf->h_name = alias[1];
			result_buf->h_addrtype = AF_INET;
			result_buf->h_length = sizeof(*in);
			result_buf->h_addr_list = (char**) addr_list;
			result_buf->h_aliases = alias + 2;
			*result=result_buf;
			ret=NETDB_SUCCESS;
#ifdef __UCLIBC_HAS_IPV6__
        } else if (type == AF_INET6 && inet_pton(AF_INET6, alias[0], in6) > 0) {
			DPRINTF("Found INET6\n");
			addr_list6[0] = in6;
			addr_list6[1] = 0;
			result_buf->h_name = alias[1];
			result_buf->h_addrtype = AF_INET6;
			result_buf->h_length = sizeof(*in6);
			result_buf->h_addr_list = (char**) addr_list6;
			result_buf->h_aliases = alias + 2;
			*result=result_buf;
			ret=NETDB_SUCCESS;
#endif /* __UCLIBC_HAS_IPV6__ */
		} else {
			DPRINTF("Error\n");
			ret=TRY_AGAIN;
			break; /* bad ip address */
        }

		if (action!=GETHOSTENT) {
			fclose(fp);
		}
		return ret;
	}
	if (action!=GETHOSTENT) {
		fclose(fp);
	}
	return ret;
}
#endif


#ifdef L_gethostent
__UCLIBC_MUTEX_STATIC(mylock, PTHREAD_MUTEX_INITIALIZER);

static int __stay_open;
static FILE * __gethostent_fp;

void endhostent (void)
{
    __UCLIBC_MUTEX_LOCK(mylock);
    __stay_open = 0;
    if (__gethostent_fp) {
	fclose(__gethostent_fp);
    }
    __UCLIBC_MUTEX_UNLOCK(mylock);
}

void sethostent (int stay_open)
{
    __UCLIBC_MUTEX_LOCK(mylock);
    __stay_open = stay_open;
    __UCLIBC_MUTEX_UNLOCK(mylock);
}

int gethostent_r(struct hostent *result_buf, char *buf, size_t buflen,
	struct hostent **result, int *h_errnop)
{
    int ret;

    __UCLIBC_MUTEX_LOCK(mylock);
    if (__gethostent_fp == NULL) {
	__open_etc_hosts(&__gethostent_fp);
	if (__gethostent_fp == NULL) {
	    *result = NULL;
	    ret = TRY_AGAIN;
	    goto DONE;
	}
    }

    ret = __read_etc_hosts_r(__gethostent_fp, NULL, AF_INET, GETHOSTENT,
		   result_buf, buf, buflen, result, h_errnop);
    if (__stay_open == 0) {
	fclose(__gethostent_fp);
    }
DONE:
    __UCLIBC_MUTEX_UNLOCK(mylock);
    return(ret);
}
libc_hidden_def(gethostent_r)

struct hostent *gethostent (void)
{
    static struct hostent h;
    static char buf[
#ifndef __UCLIBC_HAS_IPV6__
					sizeof(struct in_addr) + sizeof(struct in_addr *)*2 +
#else
					sizeof(struct in6_addr) + sizeof(struct in6_addr *)*2 +
#endif /* __UCLIBC_HAS_IPV6__ */
					sizeof(char *)*(ALIAS_DIM) +
					80/*namebuffer*/ + 2/* margin */];
    struct hostent *host;

    __UCLIBC_MUTEX_LOCK(mylock);
    gethostent_r(&h, buf, sizeof(buf), &host, &h_errno);
    __UCLIBC_MUTEX_UNLOCK(mylock);
    return(host);
}
#endif

#ifdef L_get_hosts_byname_r

int attribute_hidden __get_hosts_byname_r(const char * name, int type,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop)
{
	return(__read_etc_hosts_r(NULL, name, type, GET_HOSTS_BYNAME,
		    result_buf, buf, buflen, result, h_errnop));
}
#endif

#ifdef L_get_hosts_byaddr_r

int attribute_hidden __get_hosts_byaddr_r(const char * addr, int len, int type,
			    struct hostent * result_buf,
			    char * buf, size_t buflen,
			    struct hostent ** result,
			    int * h_errnop)
{
#ifndef __UCLIBC_HAS_IPV6__
	char	ipaddr[INET_ADDRSTRLEN];
#else
	char	ipaddr[INET6_ADDRSTRLEN];
#endif /* __UCLIBC_HAS_IPV6__ */

    switch (type) {
		case AF_INET:
			if (len != sizeof(struct in_addr))
				return 0;
			break;
#ifdef __UCLIBC_HAS_IPV6__
		case AF_INET6:
			if (len != sizeof(struct in6_addr))
				return 0;
			break;
#endif /* __UCLIBC_HAS_IPV6__ */
		default:
			return 0;
	}

	inet_ntop(type, addr, ipaddr, sizeof(ipaddr));

	return(__read_etc_hosts_r(NULL, ipaddr, type, GET_HOSTS_BYADDR,
							  result_buf, buf, buflen, result, h_errnop));
}
#endif

#ifdef L_getnameinfo

#ifndef min
# define min(x,y) (((x) > (y)) ? (y) : (x))
#endif /* min */

libc_hidden_proto(getnameinfo)
int getnameinfo (const struct sockaddr *sa, socklen_t addrlen, char *host,
				 socklen_t hostlen, char *serv, socklen_t servlen,
				 unsigned int flags)
{
	int serrno = errno;
	unsigned ok;
	struct hostent *h = NULL;
	char domain[256];

	if (flags & ~(NI_NUMERICHOST|NI_NUMERICSERV|NI_NOFQDN|NI_NAMEREQD|NI_DGRAM))
		return EAI_BADFLAGS;

	if (sa == NULL || addrlen < sizeof (sa_family_t))
		goto BAD_FAM;

	ok = sa->sa_family;
	if (ok == AF_LOCAL) /* valid */;
	else if (ok == AF_INET) {
		if (addrlen < sizeof (struct sockaddr_in))
			goto BAD_FAM;
#ifdef __UCLIBC_HAS_IPV6__
	} else if (ok == AF_INET6) {
		if (addrlen < sizeof (struct sockaddr_in6))
			goto BAD_FAM;
#endif /* __UCLIBC_HAS_IPV6__ */
	} else
BAD_FAM:
		return EAI_FAMILY;

	ok = 0;
	if (host != NULL && hostlen > 0)
		switch (sa->sa_family) {
		case AF_INET:
#ifdef __UCLIBC_HAS_IPV6__
		case AF_INET6:
#endif /* __UCLIBC_HAS_IPV6__ */
			if (!(flags & NI_NUMERICHOST)) {
#ifdef __UCLIBC_HAS_IPV6__
				if (sa->sa_family == AF_INET6)
					h = gethostbyaddr ((const void *)
						&(((const struct sockaddr_in6 *) sa)->sin6_addr),
						sizeof(struct in6_addr), AF_INET6);
				else
#endif /* __UCLIBC_HAS_IPV6__ */
                    h = gethostbyaddr ((const void *) &(((const struct sockaddr_in *)sa)->sin_addr),
					  sizeof(struct in_addr), AF_INET);

				if (h) {
					char *c;
					if ((flags & NI_NOFQDN)
					    && (getdomainname (domain, sizeof(domain)) == 0)
					    && (c = strstr (h->h_name, domain))
					    && (c != h->h_name) && (*(--c) == '.')) {
						strncpy (host, h->h_name,
							min(hostlen, (size_t) (c - h->h_name)));
						host[min(hostlen - 1, (size_t) (c - h->h_name))] = '\0';
						ok = 1;
					} else {
						strncpy (host, h->h_name, hostlen);
						ok = 1;
					}
				 }
			}

			if (!ok) {
				if (flags & NI_NAMEREQD) {
					errno = serrno;
					return EAI_NONAME;
				} else {
					const char *c;
#ifdef __UCLIBC_HAS_IPV6__
					if (sa->sa_family == AF_INET6) {
						const struct sockaddr_in6 *sin6p;

						sin6p = (const struct sockaddr_in6 *) sa;

						c = inet_ntop (AF_INET6,
							(const void *) &sin6p->sin6_addr, host, hostlen);
#if 0
						/* Does scope id need to be supported? */
						uint32_t scopeid;
						scopeid = sin6p->sin6_scope_id;
						if (scopeid != 0) {
							/* Buffer is >= IFNAMSIZ+1.  */
							char scopebuf[IFNAMSIZ + 1];
							char *scopeptr;
							int ni_numericscope = 0;
							size_t real_hostlen = strnlen (host, hostlen);
							size_t scopelen = 0;

							scopebuf[0] = SCOPE_DELIMITER;
							scopebuf[1] = '\0';
							scopeptr = &scopebuf[1];

							if (IN6_IS_ADDR_LINKLOCAL (&sin6p->sin6_addr)
							    || IN6_IS_ADDR_MC_LINKLOCAL (&sin6p->sin6_addr)) {
								if (if_indextoname (scopeid, scopeptr) == NULL)
									++ni_numericscope;
								else
									scopelen = strlen (scopebuf);
							} else {
								++ni_numericscope;
							}

							if (ni_numericscope)
								scopelen = 1 + snprintf (scopeptr,
									(scopebuf
									+ sizeof scopebuf
									- scopeptr),
									"%u", scopeid);

							if (real_hostlen + scopelen + 1 > hostlen)
								return EAI_SYSTEM;
							memcpy (host + real_hostlen, scopebuf, scopelen + 1);
						}
#endif
					} else
#endif /* __UCLIBC_HAS_IPV6__ */
						c = inet_ntop (AF_INET, (const void *)
							&(((const struct sockaddr_in *) sa)->sin_addr),
							host, hostlen);

					if (c == NULL) {
						errno = serrno;
						return EAI_SYSTEM;
					}
				}
				ok = 1;
			}
			break;

		case AF_LOCAL:
			if (!(flags & NI_NUMERICHOST)) {
				struct utsname utsname;

				if (!uname (&utsname)) {
					strncpy (host, utsname.nodename, hostlen);
					break;
				};
			};

			if (flags & NI_NAMEREQD) {
				errno = serrno;
				return EAI_NONAME;
			}

			strncpy (host, "localhost", hostlen);
			break;

/*Already checked above		default:
			return EAI_FAMILY;
*/
	}

	if (serv && (servlen > 0)) {
		if (sa->sa_family == AF_LOCAL) {
			strncpy (serv, ((const struct sockaddr_un *) sa)->sun_path, servlen);
		} else { /* AF_INET || AF_INET6 */
			if (!(flags & NI_NUMERICSERV)) {
				struct servent *s;
				s = getservbyport (((const struct sockaddr_in *) sa)->sin_port,
				      ((flags & NI_DGRAM) ? "udp" : "tcp"));
				if (s) {
					strncpy (serv, s->s_name, servlen);
					goto DONE;
				}
			}
			snprintf (serv, servlen, "%d",
				ntohs (((const struct sockaddr_in *) sa)->sin_port));
		}
	}
DONE:
	if (host && (hostlen > 0))
		host[hostlen-1] = 0;
	if (serv && (servlen > 0))
		serv[servlen-1] = 0;
	errno = serrno;
	return 0;
}
libc_hidden_def(getnameinfo)
#endif


#ifdef L_gethostbyname_r

int gethostbyname_r(const char * name,
					struct hostent * result_buf,
					char * buf, size_t buflen,
					struct hostent ** result,
					int * h_errnop)
{
	struct in_addr *in;
	struct in_addr **addr_list;
	char **alias;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int __nameserversXX;
	char ** __nameserverXX;

	__open_nameservers();
	*result=NULL;
	if (!name)
		return EINVAL;

	/* do /etc/hosts first */
	{
		int old_errno = errno;	/* Save the old errno and reset errno */
		__set_errno(0);			/* to check for missing /etc/hosts. */

		if ((i=__get_hosts_byname_r(name, AF_INET, result_buf,
									buf, buflen, result, h_errnop))==0)
			return i;
		switch (*h_errnop) {
			case HOST_NOT_FOUND:
			case NO_ADDRESS:
				break;
			case NETDB_INTERNAL:
				if (errno == ENOENT) {
					break;
				}
				/* else fall through */
			default:
				return i;
		}
		__set_errno(old_errno);
	}

	DPRINTF("Nothing found in /etc/hosts\n");

	*h_errnop = NETDB_INTERNAL;
	if (buflen < sizeof(*in))
		return ERANGE;
	in=(struct in_addr*)buf;
	buf+=sizeof(*in);
	buflen-=sizeof(*in);

	if (buflen < sizeof(*addr_list)*2)
		return ERANGE;
	addr_list=(struct in_addr**)buf;
	buf+=sizeof(*addr_list)*2;
	buflen-=sizeof(*addr_list)*2;

	addr_list[0] = in;
	addr_list[1] = 0;

	if (buflen < sizeof(char *)*(ALIAS_DIM))
		return ERANGE;
	alias=(char **)buf;
	buf+=sizeof(char **)*(ALIAS_DIM);
	buflen-=sizeof(char **)*(ALIAS_DIM);

	if (buflen<256)
		return ERANGE;
	strncpy(buf, name, buflen);

	alias[0] = buf;
	alias[1] = NULL;

	/* First check if this is already an address */
	if (inet_aton(name, in)) {
	    result_buf->h_name = buf;
	    result_buf->h_addrtype = AF_INET;
	    result_buf->h_length = sizeof(*in);
	    result_buf->h_addr_list = (char **) addr_list;
	    result_buf->h_aliases = alias;
	    *result=result_buf;
	    *h_errnop = NETDB_SUCCESS;
	    return NETDB_SUCCESS;
	}

	for (;;) {

	    __UCLIBC_MUTEX_LOCK(__resolv_lock);
	    __nameserversXX=__nameservers;
	    __nameserverXX=__nameserver;
	    __UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	    a.buf = buf;
	    a.buflen = buflen;
	    a.add_count = 0;
	    i = __dns_lookup(name, T_A, __nameserversXX, __nameserverXX, &packet, &a);

	    if (i < 0) {
			*h_errnop = HOST_NOT_FOUND;
			DPRINTF("__dns_lookup\n");
			return TRY_AGAIN;
	    }

	    /* Always try to return at least one result, if we can. */
	    while (a.add_count > 1 &&
				(a.rdlength + sizeof(struct in_addr*)) * a.add_count + 256 > buflen)
		    a.add_count--;

	    if ((a.rdlength + sizeof(struct in_addr*)) * a.add_count + 256 > buflen)
			{
				free(a.dotted);
				free(packet);
				*h_errnop = NETDB_INTERNAL;
				DPRINTF("buffer too small for all addresses\n");
				return ERANGE;
			}
	    else if(a.add_count > 0)
			{
				memmove(buf - sizeof(struct in_addr*)*2, buf, a.add_count * a.rdlength);
				addr_list = (struct in_addr**)(buf + a.add_count * a.rdlength);
				addr_list[0] = in;
				for (i = a.add_count-1; i>=0; --i)
					addr_list[i+1] = (struct in_addr*)(buf - sizeof(struct in_addr*)*2 + a.rdlength * i);
				addr_list[a.add_count + 1] = 0;
				buflen -= (((char*)&(addr_list[a.add_count + 2])) - buf);
				buf = (char*)&addr_list[a.add_count + 2];
			}

	    strncpy(buf, a.dotted, buflen);
	    free(a.dotted);

	    if (a.atype == T_A) { /* ADDRESS */
			memcpy(in, a.rdata, sizeof(*in));
			result_buf->h_name = buf;
			result_buf->h_addrtype = AF_INET;
			result_buf->h_length = sizeof(*in);
			result_buf->h_addr_list = (char **) addr_list;
#ifdef __UCLIBC_MJN3_ONLY__
#warning TODO -- generate the full list
#endif
			result_buf->h_aliases = alias; /* TODO: generate the full list */
			free(packet);
			break;
	    } else {
			free(packet);
			*h_errnop=HOST_NOT_FOUND;
			return TRY_AGAIN;
	    }
	}

	*result=result_buf;
	*h_errnop = NETDB_SUCCESS;
	return NETDB_SUCCESS;
}
libc_hidden_def(gethostbyname_r)
#endif

#ifdef L_gethostbyname2_r

int gethostbyname2_r(const char *name, int family,
					 struct hostent * result_buf,
					 char * buf, size_t buflen,
					 struct hostent ** result,
					 int * h_errnop)
{
#ifndef __UCLIBC_HAS_IPV6__
	return family == (AF_INET)? gethostbyname_r(name, result_buf,
												buf, buflen, result, h_errnop) : HOST_NOT_FOUND;
#else /* __UCLIBC_HAS_IPV6__ */
	struct in6_addr *in;
	struct in6_addr **addr_list;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int nest = 0;
	int __nameserversXX;
	char ** __nameserverXX;

	if (family == AF_INET)
		return gethostbyname_r(name, result_buf, buf, buflen, result, h_errnop);

	if (family != AF_INET6)
		return EINVAL;

	__open_nameservers();
	*result=NULL;
	if (!name)
		return EINVAL;

	/* do /etc/hosts first */
	{
		int old_errno = errno;	/* Save the old errno and reset errno */
		__set_errno(0);			/* to check for missing /etc/hosts. */

		if ((i=__get_hosts_byname_r(name, family, result_buf,
									buf, buflen, result, h_errnop))==0)
			return i;
		switch (*h_errnop) {
			case HOST_NOT_FOUND:
			case NO_ADDRESS:
				break;
			case NETDB_INTERNAL:
				if (errno == ENOENT) {
					break;
				}
				/* else fall through */
			default:
				return i;
		}
		__set_errno(old_errno);
	}

	DPRINTF("Nothing found in /etc/hosts\n");

	*h_errnop = NETDB_INTERNAL;
	if (buflen < sizeof(*in))
		return ERANGE;
	in=(struct in6_addr*)buf;
	buf+=sizeof(*in);
	buflen-=sizeof(*in);

	if (buflen < sizeof(*addr_list)*2)
		return ERANGE;
	addr_list=(struct in6_addr**)buf;
	buf+=sizeof(*addr_list)*2;
	buflen-=sizeof(*addr_list)*2;

	addr_list[0] = in;
	addr_list[1] = 0;

	if (buflen<256)
		return ERANGE;
	strncpy(buf, name, buflen);

	/* First check if this is already an address */
	if (inet_pton(AF_INET6, name, in)) {
	    result_buf->h_name = buf;
	    result_buf->h_addrtype = AF_INET6;
	    result_buf->h_length = sizeof(*in);
	    result_buf->h_addr_list = (char **) addr_list;
	    *result=result_buf;
	    *h_errnop = NETDB_SUCCESS;
	    return NETDB_SUCCESS;
	}

	memset((char *) &a, '\0', sizeof(a));

	for (;;) {
		__UCLIBC_MUTEX_LOCK(__resolv_lock);
		__nameserversXX=__nameservers;
		__nameserverXX=__nameserver;
		__UCLIBC_MUTEX_UNLOCK(__resolv_lock);

		i = __dns_lookup(buf, T_AAAA, __nameserversXX, __nameserverXX, &packet, &a);

		if (i < 0) {
			*h_errnop = HOST_NOT_FOUND;
			return TRY_AGAIN;
		}

		strncpy(buf, a.dotted, buflen);
		free(a.dotted);

		if (a.atype == T_CNAME) {		/* CNAME */
			DPRINTF("Got a CNAME in gethostbyname()\n");
			i = __decode_dotted(packet, a.rdoffset, buf, buflen);
			free(packet);

			if (i < 0) {
				*h_errnop = NO_RECOVERY;
				return -1;
			}
			if (++nest > MAX_RECURSE) {
				*h_errnop = NO_RECOVERY;
				return -1;
			}
			continue;
		} else if (a.atype == T_AAAA) {	/* ADDRESS */
			memcpy(in, a.rdata, sizeof(*in));
			result_buf->h_name = buf;
			result_buf->h_addrtype = AF_INET6;
			result_buf->h_length = sizeof(*in);
			result_buf->h_addr_list = (char **) addr_list;
			free(packet);
			break;
		} else {
			free(packet);
			*h_errnop=HOST_NOT_FOUND;
			return TRY_AGAIN;
		}
	}

	*result=result_buf;
	*h_errnop = NETDB_SUCCESS;
	return NETDB_SUCCESS;
#endif /* __UCLIBC_HAS_IPV6__ */
}
libc_hidden_def(gethostbyname2_r)
#endif

#ifdef L_gethostbyaddr_r
int gethostbyaddr_r (const void *addr, socklen_t len, int type,
					 struct hostent * result_buf,
					 char * buf, size_t buflen,
					 struct hostent ** result,
					 int * h_errnop)

{
	struct in_addr *in;
	struct in_addr **addr_list;
#ifdef __UCLIBC_HAS_IPV6__
	char *qp;
	size_t plen;
	struct in6_addr	*in6;
	struct in6_addr	**addr_list6;
#endif /* __UCLIBC_HAS_IPV6__ */
	char **alias;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int nest = 0;
	int __nameserversXX;
	char ** __nameserverXX;

	*result=NULL;
	if (!addr)
		return EINVAL;

	memset((char *) &a, '\0', sizeof(a));

	switch (type) {
		case AF_INET:
			if (len != sizeof(struct in_addr))
				return EINVAL;
			break;
#ifdef __UCLIBC_HAS_IPV6__
		case AF_INET6:
			if (len != sizeof(struct in6_addr))
				return EINVAL;
			break;
#endif /* __UCLIBC_HAS_IPV6__ */
		default:
			return EINVAL;
	}

	/* do /etc/hosts first */
	if ((i=__get_hosts_byaddr_r(addr, len, type, result_buf,
								buf, buflen, result, h_errnop))==0)
		return i;
	switch (*h_errnop) {
		case HOST_NOT_FOUND:
		case NO_ADDRESS:
			break;
		default:
			return i;
	}

	__open_nameservers();

#ifdef __UCLIBC_HAS_IPV6__
	qp=buf;
	plen=buflen;
#endif /* __UCLIBC_HAS_IPV6__ */

	*h_errnop = NETDB_INTERNAL;
	if (buflen < sizeof(*in))
		return ERANGE;
	in=(struct in_addr*)buf;
	buf+=sizeof(*in);
	buflen-=sizeof(*in);

	if (buflen < sizeof(*addr_list)*2)
		return ERANGE;
	addr_list=(struct in_addr**)buf;
	buf+=sizeof(*addr_list)*2;
	buflen-=sizeof(*addr_list)*2;

	if (buflen < sizeof(char *)*(ALIAS_DIM))
		return ERANGE;
	alias=(char **)buf;
	buf+=sizeof(*alias)*(ALIAS_DIM);
	buflen-=sizeof(*alias)*(ALIAS_DIM);

#ifdef __UCLIBC_HAS_IPV6__
	if (plen < sizeof(*in6))
		return ERANGE;
	in6=(struct in6_addr*)qp;
	qp+=sizeof(*in6);
	plen-=sizeof(*in6);

	if (plen < sizeof(*addr_list6)*2)
		return ERANGE;
	addr_list6=(struct in6_addr**)qp;
	qp+=sizeof(*addr_list6)*2;
	plen-=sizeof(*addr_list6)*2;

	if (plen < buflen) {
		buflen=plen;
		buf=qp;
	}
#endif /* __UCLIBC_HAS_IPV6__ */

	if (buflen<256)
		return ERANGE;

	if(type == AF_INET) {
		unsigned char *tmp_addr = (unsigned char *)addr;

		memcpy(&in->s_addr, addr, len);

		addr_list[0] = in;

		sprintf(buf, "%u.%u.%u.%u.in-addr.arpa",
				tmp_addr[3], tmp_addr[2], tmp_addr[1], tmp_addr[0]);
#ifdef __UCLIBC_HAS_IPV6__
	} else {
		memcpy(in6->s6_addr, addr, len);

		addr_list6[0] = in6;
		qp = buf;

		for (i = len - 1; i >= 0; i--) {
			qp += sprintf(qp, "%x.%x.", in6->s6_addr[i] & 0xf,
						  (in6->s6_addr[i] >> 4) & 0xf);
		}
		strcpy(qp, "ip6.int");
#endif /* __UCLIBC_HAS_IPV6__ */
	}

	addr_list[1] = 0;

	alias[0] = buf;
	alias[1] = 0;

	for (;;) {

		__UCLIBC_MUTEX_LOCK(__resolv_lock);
		__nameserversXX=__nameservers;
		__nameserverXX=__nameserver;
		__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
		i = __dns_lookup(buf, T_PTR, __nameserversXX, __nameserverXX, &packet, &a);

		if (i < 0) {
			*h_errnop = HOST_NOT_FOUND;
			return TRY_AGAIN;
		}

		strncpy(buf, a.dotted, buflen);
		free(a.dotted);

		if (a.atype == T_CNAME) {		/* CNAME */
			DPRINTF("Got a CNAME in gethostbyaddr()\n");
			i = __decode_dotted(packet, a.rdoffset, buf, buflen);
			free(packet);

			if (i < 0) {
				*h_errnop = NO_RECOVERY;
				return -1;
			}
			if (++nest > MAX_RECURSE) {
				*h_errnop = NO_RECOVERY;
				return -1;
			}
			continue;
		} else if (a.atype == T_PTR) {	/* ADDRESS */
			i = __decode_dotted(packet, a.rdoffset, buf, buflen);
			free(packet);

			result_buf->h_name = buf;
			result_buf->h_addrtype = type;

			if(type == AF_INET) {
				result_buf->h_length = sizeof(*in);
#ifdef __UCLIBC_HAS_IPV6__
			} else {
				result_buf->h_length = sizeof(*in6);
#endif /* __UCLIBC_HAS_IPV6__ */
			}

			result_buf->h_addr_list = (char **) addr_list;
			result_buf->h_aliases = alias;
			break;
		} else {
			free(packet);
			*h_errnop = NO_ADDRESS;
			return TRY_AGAIN;
		}
	}

	*result=result_buf;
	*h_errnop = NETDB_SUCCESS;
	return NETDB_SUCCESS;
}
libc_hidden_def(gethostbyaddr_r)
#endif

#ifdef L_res_comp
/*
 * Expand compressed domain name 'comp_dn' to full domain name.
 * 'msg' is a pointer to the begining of the message,
 * 'eomorig' points to the first location after the message,
 * 'exp_dn' is a pointer to a buffer of size 'length' for the result.
 * Return size of compressed name or -1 if there was an error.
 */
int __dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
				char *dst, int dstsiz)
{
	int n = ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

	if (n > 0 && dst[0] == '.')
		dst[0] = '\0';
	return (n);
}
#endif /* L_res_comp */

#ifdef L_ns_name
/*
 * printable(ch)
 *      Thinking in noninternationalized USASCII (per the DNS spec),
 *      is this character visible and not a space when printed ?
 * return:
 *      boolean.
 */
static int printable(int ch)
{
	return (ch > 0x20 && ch < 0x7f);
}

/*
 * special(ch)
 *      Thinking in noninternationalized USASCII (per the DNS spec),
 *      is this characted special ("in need of quoting") ?
 * return:
 *      boolean.
 */
static int special(int ch)
{
	switch (ch) {
        case 0x22: /* '"' */
        case 0x2E: /* '.' */
        case 0x3B: /* ';' */
        case 0x5C: /* '\\' */
			/* Special modifiers in zone files. */
        case 0x40: /* '@' */
        case 0x24: /* '$' */
			return (1);
        default:
			return (0);
	}
}

/*
 * ns_name_uncompress(msg, eom, src, dst, dstsiz)
 *      Expand compressed domain name to presentation format.
 * return:
 *      Number of bytes read out of `src', or -1 (with errno set).
 * note:
 *      Root domain returns as "." not "".
 */
int ns_name_uncompress(const u_char *msg, const u_char *eom,
		const u_char *src, char *dst, size_t dstsiz)
{
	u_char tmp[NS_MAXCDNAME];
	int n;

	if ((n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
		return (-1);
	if (ns_name_ntop(tmp, dst, dstsiz) == -1)
		return (-1);
	return (n);
}
libc_hidden_def(ns_name_uncompress)


/*
 * ns_name_ntop(src, dst, dstsiz)
 *      Convert an encoded domain name to printable ascii as per RFC1035.
 * return:
 *      Number of bytes written to buffer, or -1 (with errno set)
 * notes:
 *      The root is returned as "."
 *      All other domains are returned in non absolute form
 */
int ns_name_ntop(const u_char *src, char *dst, size_t dstsiz) {
	const u_char *cp;
	char *dn, *eom;
	u_char c;
	u_int n;
	const char digits[] = "0123456789";

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) != 0) {
			/* Some kind of compression pointer. */
			__set_errno (EMSGSIZE);
			return (-1);
		}
		if (dn != dst) {
			if (dn >= eom) {
				__set_errno (EMSGSIZE);
				return (-1);
			}
			*dn++ = '.';
		}
		if (dn + n >= eom) {
			__set_errno (EMSGSIZE);
			return (-1);
		}
		for ((void)NULL; n > 0; n--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = digits[c / 100];
				*dn++ = digits[(c % 100) / 10];
				*dn++ = digits[c % 10];
			} else {
				if (dn >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			__set_errno (EMSGSIZE);
			return (-1);
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		__set_errno (EMSGSIZE);
		return (-1);
	}
	*dn++ = '\0';
	return (dn - dst);
}
libc_hidden_def(ns_name_ntop)

/*
 * ns_name_unpack(msg, eom, src, dst, dstsiz)
 *      Unpack a domain name from a message, source may be compressed.
 * return:
 *      -1 if it fails, or consumed octets if it succeeds.
 */
int ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
               u_char *dst, size_t dstsiz)
{
	const u_char *srcp, *dstlim;
	u_char *dstp;
	int n, len, checked;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		__set_errno (EMSGSIZE);
		return (-1);
	}
	/* Fetch next label in domain name. */
	while ((n = *srcp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
			case 0:
				/* Limit checks. */
				if (dstp + n + 1 >= dstlim || srcp + n >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				checked += n + 1;
				*dstp++ = n;
				memcpy(dstp, srcp, n);
				dstp += n;
				srcp += n;
				break;

			case NS_CMPRSFLGS:
				if (srcp >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				if (len < 0)
					len = srcp - src + 1;
				srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
				if (srcp < msg || srcp >= eom) {  /* Out of range. */
					__set_errno (EMSGSIZE);
					return (-1);
				}
				checked += 2;
				/*
				 * Check for loops in the compressed name;
				 * if we've looked at the whole message,
				 * there must be a loop.
				 */
				if (checked >= eom - msg) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				break;

			default:
				__set_errno (EMSGSIZE);
				return (-1);                    /* flag error */
		}
	}
	*dstp = '\0';
	if (len < 0)
		len = srcp - src;
	return (len);
}
libc_hidden_def(ns_name_unpack)
#endif /* L_ns_name */
