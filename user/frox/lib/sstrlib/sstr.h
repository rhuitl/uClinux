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

  sstr.h -- Header file for secure (?) string calls.

Functions in which the standard <string.h> equivalents take two string
arguments (eg. strcat()) have two sstr equivs. sstr_cat() concatenates
two sstr buffers, while sstr_cat2() concatenates an sstr and a char[]
buffer. sstr_n...() functions will cpy/cat _exactly_ n characters, not
at most n characters like the string.h equivs.

sstr pointers should be obtained from sstr_init(), or sstrdup2()

Provided all sstr pointers have been initialised as above then none of
these functions should be overflowable.

***************************************/

#ifndef SSTR_H
#define SSTR_H

#include <stdarg.h>
#include <stdio.h>

typedef struct _sstr sstr;

/*Set general options, and callback function for serious errors
  (ie. malloc fail)*/
void sstr_setopts(void (*func) (void), int flags);

/*Get an sstr object. The size of its string will never exceed maxlen.
  If maxlen==0 the string will grow until memory runs out.

  Returns NULL on error.*/
sstr *sstr_init(int maxlen);

/*Free a previously allocated sstr. To avoid memory leaks this should
  be done for any sstr pointer returned by sstr_init() or sstr_dup()*/
void sstr_free(sstr * p);

/*Returns sstr containing buf. Needs freeing after use*/
sstr *sstr_dup(const sstr * buf);
sstr *sstr_dup2(const char *buf);

/*Return a pointer to p's internal buffer. This is guaranteed to be 
  NUL terminated only until the next sstr function call on p.*/
const char *sstr_buf(const sstr * p);

int sstr_len(const sstr * p);

/*Empty buffer*/
void sstr_empty(sstr * p);

/*strcat/strcpy replacements. Return 0 on success, -1 on failure or if
  src will not fit in dest. NOTE sstr_ncat2 and sstrncpy2 act
  differently from their standard sting.h equivalents. They will
  _always_ copy len characters, even if src appears to be shorter than
  this. This allows you to read a string containing NULs with these
  functions, but also means you can cause a segfault.*/
int sstr_cat(sstr * dest, const sstr * src);
int sstr_ncat(sstr * dest, const sstr * src, int len);
int sstr_ncat2(sstr * dest, const char *src, int len);
int sstr_cpy(sstr * dest, const sstr * src);
int sstr_cpy2(sstr * dest, const char *src);
int sstr_ncpy2(sstr * dest, const char *src, int len);

/*Compares*/
int sstr_cmp(const sstr * s1, const sstr * s2);
int sstr_cmp2(const sstr * s1, const char *s2);
int sstr_casecmp2(const sstr * s1, const char *s2);
int sstr_ncasecmp2(const sstr * s1, const char *s2, int len);

/*File I/O. If cnt==0 sstr_write() will write the whole buffer, but 
 sstr_append_read() will read nothing.*/
int sstr_append_read(int fd, sstr * p, int cnt);
int sstr_write(int fd, sstr * p, int cnt);
char *sstr_fgets(sstr * p, FILE * fp);

/*Strips any chars from "strip" from the beginning of p*/
void sstr_strip(sstr * p, const char *strip);

/*There is a token if chars not in delim are followed by chars in
 delim. Any leading chars from delim are stripped, token moved to tok,
 and then any trailing chars from delim are stripped from in. Returns
 the first delimiting char from after the token, or -1 if no token
 exists. tok may be NULL in which case in is stripped, but the token
 not stored. 

 Flags may be 0 or SSTR_QTOK in which case the token may be quoted
 with " or ' */
int sstr_token(sstr * in, sstr * tok, const char *delim, int flags);

/*Appends printf output to the end of p*/
int sstr_apprintf(sstr * p, const char *fmt, ...);

/*Remove cnt characters at offset start from in, and if out!=NULL
 * return them in that. Returns -1 if there are less than cnt chars to
 * read from start.*/
int sstr_split(sstr * in, sstr * out, int start, int cnt);

/*returns index of first occurence of c*/
int sstr_chr(const sstr * p, int c);
int sstr_pbrk2(const sstr * p, const char *accept);

int sstr_atoi(const sstr * p);
int sstr_getchar(const sstr * p, int i);
int sstr_setchar(const sstr * p, int i, int c);
#define sstr_hasline(P) (sstr_chr(P, '\n') != -1)

/*Convert all unprintable chars in p to c. Return no. of unprintables 
found*/
int sstr_makeprintable(sstr * p, int c);

#define SSTR_QTOK   1

#endif /* SSTR_H */
