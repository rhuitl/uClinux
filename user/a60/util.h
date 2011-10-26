/*
 * Copyright (C) 1991,1992 Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * This file is part of NASE A60.
 * 
 * NASE A60 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * NASE A60 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NASE A60; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * util.h:						aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef UTIL_H_HOOK
#define UTIL_H_HOOK

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


#define TALLOC(T)	((T *) xmalloc ((long) sizeof (T)))
#define NTALLOC(N,T) \
	(((N) > 0) ? (T *) xmalloc ((long) (N) * (long) sizeof (T)) : (T *) 0)
#define NTREALLOC(PTR,N,T) \
	((T *) xrealloc ((char *) PTR, (long) N * (long) sizeof (T)))

#ifndef __STDC__
extern free ();
#endif


extern int do_memstat;


extern char *xmalloc P((long));
extern char *xrealloc P((char *, long));
extern char *xstrdup P((char *s));
extern void xfree P((char *));
extern void xabort P((char *));
extern int say_goodbye P((int));
extern char *tmp_name P((void));
extern void rm_tmp P((char *));
extern int do_compile P((char *, char *));

#ifdef MEMORY_STATISTICS
extern void memstat_init P((char *));
extern void stack_stat P((char *));

#define STACK_STAT_INIT \
	int gna; \
	memstat_init ((char *) &gna);

#define DO_STACK_STAT \
	int gna; \
	stack_stat ((char *) &gna);

#endif /* MEMORY_STATISTICS */


#undef P

#endif /* UTIL_H_HOOK */
