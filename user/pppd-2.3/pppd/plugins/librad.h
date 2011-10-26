/*
 * librad.h
 *
 * (C) Copyright 2001, Lineo Inc. (www.lineo.com)
 */

#ifndef _LIBRAD_H
#define _LIBRAD_H

/* max(length) - sizeof(type) - sizeof(length) + sizeof('\0') */
#define MAX_RADIUS_ATTRIB_LEN 254

struct radius_attrib {
	u_char type;
	u_char length; /* Length of the union, not the whole attrib */
	/* XXX: should have something to say which part of union is valid */
	union { /* Only this union is network byte order */
		u_long value;
		struct in_addr addr;
		char string[MAX_RADIUS_ATTRIB_LEN]; 
	} u;
	u_long vendor;
	struct radius_attrib* next;
};

u_int radius_sessionid(void);

struct radius_attrib *radius_add_attrib(
		struct radius_attrib **list, u_long vendor, u_char type,
		u_int value, char *string, u_int length);

void radius_free_attrib(struct radius_attrib *list);

int radius_send_access_request(
		u_long host, int port, char *secret,
		struct radius_attrib *attriblist,
		struct radius_attrib **recvattriblist);

int radius_send_account_request(
		u_long host, int port, char *secret,
		struct radius_attrib *attriblist,
		struct radius_attrib **recvattriblist);

#endif
