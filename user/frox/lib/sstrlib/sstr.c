/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  sstr.c

***************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ctype.h>

#include "sstr.h"
#include "sstr_private.h"

static int sstr_cat_common(sstr * dest, const char *src, int len);

void (*on_error) (void) = NULL;

void sstr_setopts(void (*func) (void), int flags)
{
	on_error = func;
}

/* ------------------------------------------------------------- **
**  mlen=maximum no. of chars to hold. mlen=0 gives a dynamically
**  growing string.
**
**  NB. We malloc one extra byte to give space for a NUL termination,
**  but we do not use one internally. However this allows us to NUL
**  terminate our internal buffer before calling eg. atoi() on it, or
**  returning a pointer to it.
**  ------------------------------------------------------------- */
sstr *sstr_init(int mlen)
{
	sstr *ret;

	ret = malloc(sizeof(sstr));
	if(ret == NULL) {
		if(on_error)
			on_error();
		return (NULL);
	}

	if(mlen > 0) {
		ret->maxlen = mlen;
		ret->growable = 0;
	} else {
		ret->growable = 1;
		ret->maxlen = 50;
	}
	ret->buf = malloc(ret->maxlen + 1);
	if(ret->buf == NULL) {
		free(ret);
		if(on_error)
			on_error();
		return (NULL);
	}

	ret->len = 0;
	return ret;
}

void sstr_free(sstr * p)
{
	free(p->buf);
	free(p);
}

void sstr_empty(sstr * p)
{
	p->len = 0;
	sstr_alloc_space(p, 0);
}

int sstr_len(const sstr * p)
{
	return (p->len);
}

int sstr_cpy2(sstr * dest, const char *src)
{
	dest->len = 0;
	if(!src)
		return (0);
	return sstr_cat_common(dest, src, strlen(src));
}

int sstr_ncpy2(sstr * dest, const char *src, int len)
{
	dest->len = 0;
	return sstr_cat_common(dest, src, len);
}

int sstr_ncat2(sstr * dest, const char *src, int len)
{
	return sstr_cat_common(dest, src, len);
}

int sstr_cat(sstr * dest, const sstr * src)
{
	if(!src)
		return (0);

	return sstr_cat_common(dest, src->buf, src->len);
}

int sstr_ncat(sstr * dest, const sstr * src, int len)
{
	if(!src)
		return 0;
	if(len > src->len)
		len = src->len;
	return sstr_cat_common(dest, src->buf, len);
}

int sstr_cpy(sstr * dest, const sstr * src)
{
	dest->len = 0;
	if(!src)
		return (0);
	return sstr_cat_common(dest, src->buf, src->len);
}

const char *sstr_buf(const sstr * p)
{
	p->buf[p->len] = 0;
	return p->buf;
}

sstr *sstr_dup(const sstr * buf)
{
	sstr *ret;

	ret = sstr_init(0);
	sstr_cpy(ret, buf);
	return (ret);
}

sstr *sstr_dup2(const char *buf)
{
	sstr *ret;

	ret = sstr_init(0);
	sstr_cpy2(ret, buf);
	return (ret);
}

int sstr_casecmp2(const sstr * s1, const char *s2)
{
	if(!s2)
		return (-1);
	return (strcasecmp(sstr_buf(s1), s2));
}

int sstr_ncasecmp2(const sstr * s1, const char *s2, int len)
{
	if(!s2)
		return (-1);
	return (strncasecmp(sstr_buf(s1), s2, len));
}

int sstr_cmp(const sstr * s1, const sstr * s2)
{
	return (strcmp(sstr_buf(s1), sstr_buf(s2)));
}

int sstr_cmp2(const sstr * s1, const char *s2)
{
	if(!s2)
		return (-1);
	return (strcmp(sstr_buf(s1), s2));
}

int sstr_atoi(const sstr * p)
{
	return (atoi(sstr_buf(p)));
}

int sstr_chr(const sstr * p, int c)
{
	int i;
	if(c > 127)
		c -= 256;
	for(i = 0; i < p->len; i++)
		if(p->buf[i] == c)
			return (i);

	return (-1);
}

int sstr_pbrk2(const sstr * p, const char *accept)
{
	int i;
	for(i = 0; i < p->len; i++)
		if(strchr(accept, p->buf[i]))
			return (i);

	return (-1);
}

void sstr_strip(sstr * p, const char *strip)
{
	int i;
	for(i = 0; i < p->len && strchr(strip, p->buf[i]); i++);
	sstr_split(p, NULL, 0, i);
}

int sstr_token(sstr * in, sstr * tok, const char *delim, int flags)
{
	int sep, quote, i;
	if(in->len == 0)
		return (-1);

	sstr_strip(in, delim);

	if((flags & SSTR_QTOK) && (*in->buf == '"' || *in->buf == '\'')) {
		quote = *in->buf;
		for(i = 1; i < in->len && in->buf[i] != quote; i++);
		if(i == in->len)
			return (-1);
		sstr_split(in, tok, 1, i - 1);
		sstr_split(in, NULL, 0, 2);	/* Remove quotes */
	} else {
		if((i = strcspn(sstr_buf(in), delim)) >= in->len)
			return (-1);
		sstr_split(in, tok, 0, i);
	}
	sep = *in->buf;
	sstr_strip(in, delim);

	return (sep);
}

int sstr_getchar(const sstr * p, int i)
{
	if(i >= p->len || i < 0)
		return (-1);
	return (p->buf[i]);
}

int sstr_setchar(const sstr * p, int i, int c)
{
	if(i >= p->len || i < 0)
		return (-1);
	p->buf[i] = c;
	return (0);
}

int sstr_split(sstr * in, sstr * out, int start, int cnt)
{
	sstr *tmp;
	if(start + cnt > in->len || start < 0 || cnt < 0)
		return (-1);

	if(out)
		sstr_empty(out);
	if(!cnt)
		return (0);

	if(out)
		sstr_cat_common(out, in->buf + start, cnt);

	tmp = sstr_init(0);
	sstr_cat_common(tmp, in->buf, start);
	sstr_cat_common(tmp, in->buf + start + cnt, in->len - start - cnt);
	sstr_cpy(in, tmp);
	sstr_free(tmp);

	return (0);
}

int sstr_makeprintable(sstr * p, int c)
{
	int i, j = 0;

	for(i = 0; i < p->len; i++) {
		if(!isprint(p->buf[i])) {
			p->buf[i] = c;
			j++;
		}
	}
	return (j);
}

/**************************************
 * Memory management stuff. Be careful.
 **************************************/

static int sstr_cat_common(sstr * dest, const char *src, int len)
{
	int needed_bytes = dest->len + len;

	if(src == NULL || len == 0)
		return (0);
	if(len < 0)
		return (-1);

	if(dest->growable)
		sstr_alloc_space(dest, needed_bytes);
	if(dest->maxlen < needed_bytes)
		return -1;

	memcpy(dest->buf + dest->len, src, len);
	dest->len += len;
	return (0);
}

/*Ensure we have enough space for len bytes in p. This involves 
 *allocating len+1 to allow space for null termination when needed. */
int sstr_alloc_space(sstr * p, int len)
{
	char *tmp;

	len++;

	if(!p->growable && p->maxlen < len)
		return -1;
	if(!p->growable)
		return 0;
	if(p->maxlen >= len && p->maxlen - len < 50)
		return 0;

	tmp = realloc(p->buf, len + 25);
	if(!tmp) {
		if(on_error)
			on_error();
		return -1;
	}
	p->buf = tmp;
	p->maxlen = len + 25;
	return 0;
}
