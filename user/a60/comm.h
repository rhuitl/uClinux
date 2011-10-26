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
 * comm.h:					oct '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * some common stuff for the sources.
 */

#ifndef COMM_H_HOOK
#define COMM_H_HOOK

#include <stdio.h>
#include <math.h>


#ifdef AMIGA
/* not in stdio.h: */
extern FILE *freopen ();
#endif


/*
 * define NO_ENUMS, if the header files are changed (see ENUM.README).
 */

#ifdef NO_ENUMS
#define ENUM
#else /* ! NO_ENUMS */
#define ENUM enum
#endif /* ! NO_ENUMS */

/*
 * use prototypes with ANSI C  (e.g. GNU C):
 */

#ifndef USE_PROTOTYPES
#ifdef __GNUC__
#ifdef __STDC__
#ifdef unix
#define USE_PROTOTYPES
#endif /* unix */
#endif /* __STDC__ */
#endif /* __GNUC__ */
#endif /* ! USE_PROTOTYPES */



#ifdef USE_PROTOTYPES
#ifndef _POSIX_SOURCE

#ifdef __STDC__
#define	P(s) s
typedef void *VOID_P;
#else
#define P(s) ()
typedef char *VOID_P;
#endif

#ifndef THIS_IS_A60_LEX
extern char *malloc P((unsigned int n));
extern char *calloc P((unsigned int n, unsigned int s));
extern char *realloc P((char *p, unsigned int n));
extern int free P((char *p));
#endif

/*
 * most of the following declarations are originally from Stefan Petri
 * (petri@ibr.cs.tu-bs.de) - thanks.
 */

extern int strlen P((const char *));
extern int strcmp P((const char *, const char *));
extern int strncmp P((char *, char *, int));
extern char *strcat P((char *, char *));

#ifdef USG
extern void exit P((int s));
extern void perror P((char *s));
#else
extern void exit P((const int s));
extern int perror P((char *s));
extern int bcopy P((char *s1, char *s2, int n));
#endif

extern int sleep P((unsigned s));

#include <setjmp.h>
extern int setjmp P((jmp_buf env));
#ifdef sun
extern void longjmp P((jmp_buf env, int val));
#else /* ! sun */
extern int longjmp P((jmp_buf, int));
#endif /* ! sun */

extern int system P((char *s));
extern int pclose P((FILE *f));
extern FILE *popen P((char *c, char *t));
extern FILE *fopen P((char *s, char *m));
extern int printf P((char *s, ...));
extern int fprintf P((FILE *f, char *s, ...));
extern int _filbuf P((FILE *f));	/* to keep gcc -Wall happy */
extern int _flsbuf P((unsigned char c, FILE *f));
extern int setbuf P((FILE *f, char *b));
extern int fflush P((FILE *f));
extern int fgetc P((FILE *f));
extern int read P((int, char *, int));
extern int ungetc P((int c, FILE *f));
extern int atoi P((char *s));
extern int sscanf P((char *s, char *f, ...));
extern int scanf P((char *f, ...));
extern int fscanf P((FILE *, char *f, ...));
extern int fputs P((char *s, FILE *f));
extern int fputc P((int c, FILE *f));
extern int fseek P((FILE *f, long o, int p));
extern int fclose P((FILE *f));
extern int puts P((char *s));
extern long time P((long *));
extern int dup2 P((int, int));

#endif /* ! _POSIX_SOURCE */
#else /* ! USE_PROTOTYPES */

/*
 * some externals:
 * (this is surely not the best choice...)
 */
#ifdef __STDC__
#include <string.h>
#else /* ! __STDC__ */
extern strlen ();
extern strcmp ();
extern char *strcpy ();
extern char *strcat ();
#endif /* ! __STDC__ */

#ifndef __STDC__
#ifndef MSDOS
extern printf ();
extern fprintf ();
extern sscanf ();
extern fputs ();
extern read ();
extern void exit ();
#endif /* MSDOS */
#endif /* __STDC__ */

#endif /* ! USE_PROTOTYPES */

#undef P

#endif /* COMM_H_HOOK */
