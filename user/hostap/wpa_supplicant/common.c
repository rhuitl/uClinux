/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / common helper functions, etc.
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "common.h"


int hostapd_get_rand(u8 *buf, size_t len)
{
	FILE *f;
	size_t rc;

	f = fopen("/dev/urandom", "r");
	if (f == NULL) {
		printf("Could not open /dev/urandom.\n");
		return -1;
	}

	rc = fread(buf, 1, len, f);
	fclose(f);

	return rc != len ? -1 : 0;
}


void hostapd_hexdump(const char *title, u8 *buf, size_t len)
{
	size_t i;
	printf("%s - hexdump(len=%d):", title, len);
	for (i = 0; i < len; i++)
		printf(" %02x", buf[i]);
	printf("\n");
}


static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}


static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}


int hwaddr_aton(const char *txt, u8 *addr)
{
	int i;

	for (i = 0; i < 6; i++) {
		int a, b;

		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}

	return 0;
}


int hexstr2bin(const char *hex, u8 *buf, size_t len)
{
	int i, a;
	const char *ipos = hex;
	char *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}


char * rel2abs_path(const char *rel_path)
{
	char *buf = NULL, *cwd, *ret;
	size_t len = 128, cwd_len, rel_len, ret_len;

	if (rel_path[0] == '/')
		return strdup(rel_path);

	for (;;) {
		buf = malloc(len);
		if (buf == NULL)
			return NULL;
		cwd = getcwd(buf, len);
		if (cwd == NULL) {
			free(buf);
			if (errno != ERANGE) {
				return NULL;
			}
			len *= 2;
		} else {
			break;
		}
	}

	cwd_len = strlen(cwd);
	rel_len = strlen(rel_path);
	ret_len = cwd_len + 1 + rel_len + 1;
	ret = malloc(ret_len);
	if (ret) {
		memcpy(ret, cwd, cwd_len);
		ret[cwd_len] = '/';
		memcpy(ret + cwd_len + 1, rel_path, rel_len);
		ret[ret_len - 1] = '\0';
	}
	free(buf);
	return ret;
}


void inc_byte_array(u8 *counter, size_t len)
{
	int pos = len - 1;
	while (pos >= 0) {
		counter[pos]++;
		if (counter[pos] != 0)
			break;
		pos--;
	}
}
