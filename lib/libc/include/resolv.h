/* resolv.h: DNS Resolver
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 */

#ifndef _RESOLV_H_
#define _RESOLV_H_

#include <netdb.h>
#include <netinet/in.h>

#define MAXNS 5

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
	unsigned char * rdata;
	int rdoffset;
};

int encode_header(struct resolv_header * h, unsigned char * dest, int maxlen);
int decode_header(unsigned char * data, struct resolv_header * h);
int encode_dotted(const char * dotted, unsigned char * dest, int maxlen);
int decode_dotted(const unsigned char * message, int offset, 
	char * dest, int maxlen);
int length_dotted(const unsigned char * message, int offset);
int encode_question(struct resolv_question * q,
	unsigned char * dest, int maxlen);
int decode_question(unsigned char * message, int offset,
	struct resolv_question * q);
int length_question(unsigned char * message, int offset);
int encode_answer(struct resolv_answer * a,
	unsigned char * dest, int maxlen);
int decode_answer(unsigned char * message, int offset,
	struct resolv_answer * a);
char * resolve_name(const char * name, int mailbox);

int encode_packet(struct resolv_header * h,
	struct resolv_question ** q,
	struct resolv_answer ** an,
	struct resolv_answer ** ns,
	struct resolv_answer ** ar,
	unsigned char * dest, int maxlen);
int decode_packet(unsigned char * data, struct resolv_header * h);

int dns_lookup(const char * name, int type, int nscount, const char ** nsip,
	unsigned char ** outpacket, struct resolv_answer * a);

int resolve_address(const char * address, 
	int nscount, const char ** nsip, 
	struct in_addr * in);

int resolve_mailbox(const char * address, 
	int nscount, const char ** nsip, 
	struct in_addr * in);

extern int open_nameservers(void);
extern void close_nameservers(void);

extern struct hostent * gethostbyname(const char * name);
extern struct hostent * gethostbyaddr(const char * addr, int len, int type);

#endif /*_RESOLV_H_*/
