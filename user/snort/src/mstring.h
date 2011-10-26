/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */

#ifndef __MSTRING_H__
#define __MSTRING_H__

/*  I N C L U D E S  ******************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>




/*  P R O T O T Y P E S  *************************************************/
char **mSplit(char *, char *, int, int *, char);
void mSplitFree(char ***toks, int numtoks);
int mContainsSubstr(char *, int, char *, int);
int mSearch(char *, int, char *, int, int *, int *);
int mSearchCI(char *, int, char *, int, int *, int *);
int mSearchREG(char *, int, char *, int, int *, int *);
int *make_skip(char *, int);
int *make_shift(char *, int);




#endif  /* __MSTRING_H__ */
