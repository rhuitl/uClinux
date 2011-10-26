/*
 * parsers.c
 *
 * $Id: ftypes.c,v 1.3 2006/02/20 08:02:24 andrzej Exp $
 *
 * Redboot Flash Configuration parser. 
 * Argument parsers. 
 *
 * Copyright (C) 2006 Ekiert sp z o.o.
 * Author: Andrzej Ekiert <a.ekiert@ekiert.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version. 
 */

/* For inet_aton() and inet_ntoa() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* For ether_aton */
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "ftypes.h"
#include "debug.h"

/*
 * The table of all supported types. 
 */
type_t types[NUM_TYPES] = {
	{"empty", SIZE_EMPTY, NULL, NULL},
	{"bool", SIZE_BOOL, parse_bool, print_bool},
	{"int", SIZE_INT, parse_int, print_int},
	{"string", SIZE_STRING, parse_string, print_string},
	{"script", SIZE_SCRIPT, parse_script, print_script},
	{"ip", SIZE_IP, parse_ip, print_ip},
	{"esa", SIZE_ESA, parse_esa, print_esa},
	{"netport", SIZE_NETPORT, parse_netport, print_netport}
};

int8_t verify_ftype(uint8_t type)
{
	return (type < NUM_TYPES);
}

/* All parsers return non-zero code on failure */

/*
 * Convert a string to a boolean. 
 * Buffer 'buf' must be at least 4 bytes long and aligned for uint32_t. 
 */
int8_t parse_bool(uint8_t *text, void *buf)
{
	if (strcasecmp(text, "TRUE")==0) {
		*(uint32_t*)buf = 1;
		return 0;
	} else if (strcasecmp(text, "FALSE")==0) {
		*(uint32_t*)buf = 0;
		return 0;
	} else {
		return -1;
	}
	return 0;
}

/*
 * Print 'TRUE' or 'FALSE'. 
 */
void print_bool(void *buf)
{
	uint32_t val;
	memcpy(&val, buf, sizeof(val));

	if (val) {
		printf("TRUE");
	} else {
		printf("FALSE");
	}
}

/*
 * Convert a string to a 32 bit unsigned integer. 
 * Buffer 'buf' must be at least 4 bytes long and aligned for uint32_t.
 */
int8_t parse_int(uint8_t *text, void *buf)
{
	errno = 0;
	*(uint32_t*)buf = strtoul(text, (char**)NULL, 0);
	return errno;
}

/*
 * Print a 32 bit unsigned integer. 
 * 'buf' should point to such integer. 
 */
void print_int(void *buf)
{
	uint32_t val;
	memcpy(&val, buf, sizeof(val));
	printf("%d", val);
}

/*
 * Parsing a string is nothing but copying up to MAX_STRING_LENGTH-1 characters
 * from 'text' to 'buf'. Copying fails, if the result is not null-terminated.
 */
int8_t parse_string(uint8_t *text, void *buf)
{
	uint8_t *dest = (uint8_t*)buf;
	dest[MAX_STRING_LENGTH-1]='\0';
	strncpy(dest, text, MAX_STRING_LENGTH);
	if (dest[MAX_STRING_LENGTH-1]!='\0') {
		dest[MAX_STRING_LENGTH-1]='\0';
		return -1;
	}
	return 0;
}

/*
 * Print a string. 
 */
void print_string(void *buf)
{
	uint8_t *str = (uint8_t*)buf;
	printf("%s", str);
}

/*
 * Parsing a script is nothing but copying up to MAX_SCRIPT_LENGTH-1 characters
 * from 'text' to 'buf', except that all '\' characters replaced with newlines. 
 * Copying fails, if the result is not null-terminated.
 * Returns 0 on failure.
 */
int8_t parse_script(uint8_t *text, void *buf)
{
	uint8_t *dest = (uint8_t*)buf;
	dest[MAX_SCRIPT_LENGTH-1]='\0';
	strncpy(dest, text, MAX_SCRIPT_LENGTH);
	if (dest[MAX_SCRIPT_LENGTH-1]!='\0') {
		dest[MAX_SCRIPT_LENGTH-1]='\0';
		return -1;
	}
	while (*dest!='\0') {
		if (*dest == '\\') {
			*dest = '\n';
		}
		dest++;
	}
	return 0;
}

/*
 * Print a script. 
 */
void print_script(void *buf)
{
	uint8_t *str = (uint8_t*)buf;
	printf("%s", str);
}

/*
 * Convert dotted-decimal IPv4 address string into binary data. 
 * Buffer 'buf' must be able to hold 'struct in_addr' (4 bytes currently). 
 * The buffer must be aligned. 
 */
int8_t parse_ip(uint8_t *text, void *buf)
{
	return !inet_aton(text, buf);
}

/*
 * Print an IPv4 address in dotted-decimal notation. 
 */
void print_ip(void *buf)
{
	struct in_addr addr;
	memcpy(&addr, buf, sizeof(addr));
	printf("%s", inet_ntoa(addr));
}

/*
 * Convert a string containing ethernet MAC address 
 * in a "01:23:45:67:89:ab" form to a 6 byte table. 
 * Buffer 'buf' must be able to hold 'struct ether_addr' (6 bytes currently). 
 */
int8_t parse_esa(uint8_t *text, void *buf)
{
	struct ether_addr *addr = ether_aton(text);
	if (addr == NULL) {
		return -1;
	}
	memcpy(buf, addr, sizeof(struct ether_addr));
	return 0;
}

/*
 * Convert to a standard colon-separated string and print 
 * an ethernet MAC address. 
 */
void print_esa(void *buf)
{
	uint8_t *e = (uint8_t*)buf;
	printf("%02x:%02x:%02x:%02x:%02x:%02x", 
		e[0], e[1], e[2], e[3], e[4], e[5]);
}

/*
 * Parse 'netport' name. 
 * 'NETPORT' is just a string. 
 */
int8_t parse_netport(uint8_t *text, void *buf)
{
	return parse_string(text, buf);
}

/*
 * Print 'netport' name. 
 * 'NETPORT' is just a string. 
 */
void print_netport(void *buf)
{
	print_string(buf);
}

