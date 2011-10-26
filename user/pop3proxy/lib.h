/*

    File: lib.h
 
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

#ifndef	_LIB_INCLUDED
#define	_LIB_INCLUDED


extern char *program;
extern int verbose;


void *allocate(size_t size);
void *reallocate(void *p, size_t size);

unsigned int uppercase(unsigned int c);
int isuppercase(unsigned int c);
unsigned int lowercase(unsigned int c);
int islowercase(unsigned int c);
char *strlwr(char *string);
char *strupr(char *string);
char *skip_ws(char *string);
char *noctrl(char *buffer);
char *get_word(char **from, char *to, int maxlen);
char *get_quoted(char **from, int delim, char *to, int max);
int split(char *line, char *ptr[], int seq, int max);
char *copy_string(char *y, char *x, int len);
int strpcmp(char *string, char *pattern);

#endif

