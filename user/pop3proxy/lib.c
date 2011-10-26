/*

    File: lib.c
    
    Copyright (C) 1999 by Wolfgang Zekoll <wzk@quietsche-entchen.de>

    This source is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2, or (at your option)
    any later version.

    This source is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "lib.h"

#define	DEBUG(x)		


void *allocate(size_t size)
{
	void	*p;

	if ((p = malloc(size)) == NULL) {
		fprintf (stderr, "%s: memory allocation error\n", program);
		exit (-1);
		}

	memset(p, 0, size);
	return (p);
}

void *reallocate(void *p, size_t size)
{
	if ((p = realloc(p, size)) == NULL) {
		fprintf (stderr, "%s: memory allocation error\n", program);
		exit (-1);
		}

	return (p);
}



static unsigned int lower[256], upper[256];

static int _init_upper()
{
	unsigned int c;
	
	DEBUG( fprintf (stderr, "init upper[]\n"); )
	for (c = 0; c < 256; c++)
		upper[c] = c;

	DEBUG( fprintf (stderr, "init uppercase letters\n"); )
	for (c = 'a'; c < 'z'+1; c++)
		upper[c] = 'A' + (c - 'a');

	DEBUG( fprintf (stderr, "init umlaute\n"); )
	upper[c = (unsigned char) 'ä'] = 'Ä';
	upper[c = (unsigned char) 'ö'] = 'Ö';
	upper[c = (unsigned char) 'ü'] = 'Ü';

	DEBUG( fprintf (stderr, "init upper[] complete\n"); )
	return (0);
}

static int _init_lower()
{
	unsigned int c;
	
	DEBUG( fprintf (stderr, "init lower[]\n"); )
	for (c = 0; c < 256; c++)
		lower[c] = c;

	DEBUG( fprintf (stderr, "init uppercase letters\n"); )
	for (c = 'A'; c < 'Z'+1; c++)
		lower[c] = 'a' + (c - 'A');

	DEBUG( fprintf (stderr, "init umlaute\n"); )
	lower[c = (unsigned char) 'Ä'] = 'ä';
	lower[c = (unsigned char) 'Ö'] = 'ö';
	lower[c = (unsigned char) 'Ü'] = 'ü';

	DEBUG( fprintf (stderr, "init upper[] complete\n"); )
	return (0);
}


unsigned int uppercase(unsigned int c)
{
	if (upper['0'] == 0)
		_init_upper();

	return (upper[c]);
}

int isuppercase(unsigned int c)
{
	if (upper['0'] == 0)
		_init_upper();

	return (upper[c] == c);
}

unsigned int lowercase(unsigned int c)
{
	if (lower['0'] == 0)
		_init_lower();

	return (lower[c]);
}

int islowercase(unsigned int c)
{
	if (lower['0'] == 0)
		_init_lower();

	return (lower[c] == c);
}

char *strlwr(char *string)
{
	unsigned int c;
	unsigned char *p;

	if (lower['0'] == 0)
		_init_lower();
		
	p = string;
	while ((c = *p) != 0) {
		*p++ = lower[c];
		}

	return (string);
}	

char *strupr(char *string)
{
	unsigned int c;
	unsigned char *p;

	if (upper['0'] == 0)
		_init_upper();
		
	p = string;
	while ((c = *p) != 0) {
		*p++ = upper[c];
		}

	return (string);
}	

char *skip_ws(char *string)
{
	unsigned int c;

	while ((c = *string) == ' '  ||  c == '\t')
		string++;

	return (string);
}

char *noctrl(char *buffer)
{
	int	len, i;
	unsigned char *p;

	if ((p = buffer) == NULL)
		return (NULL);

	len = strlen(p);
        for (i=len-1; i>=0; i--) {
		if (p[i] <= 32)
			p[i] = '\0';
		else
			break;
		}

	return (p);
}

char *get_word(char **from, char *to, int maxlen)
{
	unsigned int c;
	unsigned char *p;
	int	k;

	maxlen -= 2;
	while ((c = **from) != 0  &&  c <= 32)
		*from += 1;

	*(p = to) = k = 0;
	while ((c = **from) != 0) {
		if (c == ' '  ||  c == '\t'  ||  c < 32)
			break;

		*from += 1;
		if (k < maxlen)
			p[k++] = c;
		}

	p[k] = 0;
	return (to);
}

char *get_quoted(char **from, int delim, char *to, int max)
{
	unsigned int c;
	int	k;

	to[0] = k = 0;
	max -= 2;
	
	while ((c = **from) != 0) {
		*from += 1;
		if (c == delim)
			break;

		if (k < max)
			to[k++] = c;
		}

	to[k] = 0;
	return (to);
}

int split(char *line, char *ptr[], int sep, int max)
{
	char	*p;
	int	k, c;

	if (line[0] == 0) {
		ptr[0] = line;
		return (0);
		}

	p = line;
	k = 0;
	while (*p != 0	&&  k < max) {
		if (sep == ' ') {
			while ((c = *p) == ' '	||  c == '\t')
				p++;
			}

		ptr[k++] = p;
		if (sep == ' ') {
			while ((c = *p) != 0  &&  c != '\t'  &&  c != ' ')
				p++;
			}
		else {
			while ((c = *p) != 0  &&  c != sep)
				p++;
			}

		if (*p != 0)
			*p++ = 0;
		}

	return (k);
}

char *copy_string(char *y, char *x, int len)
{
	x = skip_ws(x);
	noctrl(x);

	len -= 2;
	if (strlen(x) >= len)
		x[len] = 0;

	if (y != x)
		strcpy(y, x);
		
	return (y);
}

int strpcmp(char *string, char *pattern)
{
	if (*string == 0) {
		if (*pattern == 0)
			return (0);
		else if (*pattern == '*')
			return (strpcmp(string, pattern + 1));
		else
			return (1);
		}

	if (*pattern == '*') {
		while (strpcmp(string, pattern + 1) != 0) {
			string++;
			if (*string == 0) {
				if (*(pattern + 1) != 0)
					return (1);
				else
					return (0);
				}
			}

		return (0);
		}
	else if (*pattern == '?')
		return (strpcmp(string + 1, pattern + 1));
	else if (tolower(*string) == tolower(*pattern))
		return (strpcmp(string + 1, pattern + 1));

	return (1);
}

