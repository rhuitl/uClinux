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
 * util.c:						aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * set of utilities: x[re|m]alloc(), xstrdup(), xabort().
 * here is although the code for the memory statistics:
 */

#include "comm.h"
#include "util.h"
#include "a60.h"
#include "config.h"


#ifdef MEMORY_STATISTICS

/*
 * check memory-usage with our own allocation fun.
 */

typedef struct _memchunk {
	long length;
	char data[1];		/* choose 0 whith __GNUC__ ?? */
} MEMCHUNK;

#define MEM_OFFS	(sizeof(double))


/*
 * let's have a look at the used stack/heap size.
 */

static char *first_stack, *last_stack;
static long stack_siz, heap_siz, act_heap_siz;


/*
 * initialize the memory statistics.
 */

void
memstat_init (gna)
char *gna;
{
	first_stack = last_stack = gna;
	stack_siz = heap_siz = act_heap_siz = 0;
}


void
stack_stat (gna)
char *gna;
{
	int grows_up;
	int fred;
	char *fptr;

	fptr = (char *) &fred;

	grows_up = fptr > gna;

	if (grows_up) {
		if (fptr > last_stack) {
			stack_siz += fptr - last_stack;
			last_stack = fptr;
		}
	}
	else {
		if (fptr < last_stack) {
			stack_siz += last_stack - fptr;
			last_stack = fptr;
		}
	}
}



static void
give_mem_stat ()
{
	fprintf (stderr, "\nmemory statistics:\n");
	fprintf (stderr, "  recognized stacksize: 0x%lx (%ld) bytes\n",
		 stack_siz, stack_siz);
	fprintf (stderr, "  recognized heapsize:  0x%lx (%ld) bytes\n",
		 heap_siz, heap_siz);

#ifdef unix
#ifndef USG
	printf ("\n");
	system ("ps -v");
#endif /* ! USG */
#endif /* unix */
}

#endif /* MEMORY_STATISTICS */



/*
 * lets have a workaround, if realloc is not avail.
 */

#ifdef REALLOC_MISSING
char *
realloc (s, n)
char *s;
unsigned int n;
{
	extern char *malloc();
	char *str;
	int i;

	str = malloc (n);

	if (! str)
		return str;

	for (i=0; i<n; i++)
		str[i] = s[i];
	free (s);

	return str;
}
#endif


/*
 * the simple allocation routines; the program is aborted on failure.
 */

char *
xstrdup (s)
char *s;
{
	char *str;
	extern char *strcpy ();

	str = xmalloc ((long) (strlen (s) + 1));
	(void) strcpy (str, s);

	return str;
}

char *
xmalloc (n)
long n;
{
	extern char *calloc ();
	char *str;
	long nelm = 1, siz = n;

#ifdef AMIGA
	if (n > 64000l)
		xabort ("xmalloc: chunk too large");
#endif

#ifdef MEMORY_STATISTICS
	siz = siz + MEM_OFFS;
#endif

	if (sizeof(unsigned) <= 2) {
		while (siz > 32000) {
			siz = (siz + 1) / 2;
			nelm *= 2;
		}
		if (nelm > 32000)
			xabort ("xmalloc: chunk too large for 16 bit machine");
	}

	str = calloc ((unsigned) nelm, (unsigned) siz);

#ifdef MEMORY_STATISTICS
	if (str) {
		((MEMCHUNK *) str) -> length = n;
		str += MEM_OFFS;
		act_heap_siz += n;
		if (act_heap_siz > heap_siz)
			heap_siz = act_heap_siz;
	}
#endif

	if (! str) {
		xabort ("xmalloc: Oops - Out Of Mem");
	}

#ifdef DEBUG
	if (do_memdebug)
		printf ("### malloc:  %ld  [%ld * %ld]  0x%lx  bytes\n",
			n, nelm, siz, (long) str);
#endif /* DEBUG */

	return str;
}


char *
xrealloc (s, n)
char *s;
long n;
{
	extern char *realloc ();
	char *str;
#ifdef MEMORY_STATISTICS
	long siz = n;
#endif

	if (sizeof(unsigned) <= 2 && n > 64000l) {
		xabort ("xrealloc: chunk too large for 16 bit machine");
	}

#ifdef MEMORY_STATISTICS
	s -= MEM_OFFS;
	siz = siz + MEM_OFFS;
	
	act_heap_siz -= ((MEMCHUNK *) s) -> length;

	str = realloc (s, (unsigned) siz);

	if (str) {
		((MEMCHUNK *) str) -> length = n;
		str += MEM_OFFS;
		act_heap_siz += n;
		if (act_heap_siz > heap_siz)
			heap_siz = act_heap_siz;
	}
#else
	str = realloc (s, (unsigned) n);
#endif

	if (! str) {
		xabort ("xrealloc: Oops - Out Of Mem");
	}
	
#ifdef DEBUG
	if (do_memdebug)
		printf ("### realloc:  %ld  0x%lx  bytes\n", n, (long) str);
#endif /* DEBUG */

	return str;
}


void
xfree (s)
char *s;
{
#ifdef DEBUG
	if (do_memdebug)
		printf ("###  free :  0x%lx\n", (long) s);
#endif /* DEBUG */

#ifdef MEMORY_STATISTICS
	s -= MEM_OFFS;
	act_heap_siz -= ((MEMCHUNK *) s) -> length;
#endif

#ifdef __STDC__
	free (s);
#else /* ! __STDC__ */
#ifdef unix
	if (! free (s)) {
		xabort ("INTERNAL: error in free");
	}
#else /* ! unix */
#ifdef AMIGA
	if (free (s) < 0) {
		xabort ("INTERNAL: error in free");
	}
#else /* ! AMIGA */
	free (s);
#endif /* ! AMIGA */
#endif /* ! unix */
#endif /* ! __STDC__ */
}

void
xabort (s)
char *s;
{
#ifdef AMIGA
    /*
     * amiga gets sometimes a guru after this call,
     * if out of mem (?) :-( 
     * Doctor - Doctor it hurts when I do it !
     */
#endif
	fprintf (stderr, "\nFatal: %s\nAborting.\n", s);
	exit (100);
}


/*
 * anything is fine; cleanup and return.
 */

int
say_goodbye (n)
int n;
{
	extern int verbose;

#ifdef MEMORY_STATISTICS

	if (do_memstat)
		give_mem_stat ();

#endif /* MEMORY_STATISTICS */

	if (verbose)
		fprintf (stderr, "\nbye.\n");

	return n;
}


/*
 * find a temporary file filename; used for c code souce file.
 */

char *
tmp_name ()
{
#ifdef unix
	return "/tmp/mkc-onk.c";
#else
	return "mkctmp.c";
#endif
}


/*
 * remove the given file:
 */

void
rm_tmp (s)
char *s;
{
#ifdef unix
	extern int unlink ();

	(void) unlink (s);
#else /* ! unix */
#ifdef AMIGA
	extern int DeleteFile ();

	(void) DeleteFile (s);
#else /* ! AMIGA */
	fprintf (stderr, "hint: don't know how to unlink `%s'...\n", s);
#endif /* ! AMIGA */
#endif /* ! unix */
}


/*
 * compile the given file; create special output file if requested.
 */

int
do_compile (oname, outfname)
char *oname, *outfname;
{
	extern int make_c_verbose;

	if (verbose)
		fprintf (stderr, "compiling C output ...\n");
#ifdef unix
{
	char tmp[256];
	int rc;

	if (! outfname)
		outfname = "a.out";
	sprintf (tmp, "%s %s %s-o '%s' '%s' -lm", CC_TO_USE, CC_OPTS,
		 (make_c_verbose) ? "-v " : "",
		 outfname, oname);
	if (make_c_verbose)
		fprintf (stderr, "executing `%s'...\n", tmp);
	rc = system (tmp);
	return rc >> 8;
}
#else /* ! unix */
#ifdef AMIGA
{
	int rc;

	if (! outfname)
		outfname = "a.out";

	rc = fexecl ("cc", "cc", "-o", "tmpmkctmp.o", oname,
			(char *) 0);
	if (! rc) {
		rc = fexecl ("ln", "ln", "-o", outfname, "tmpmkctmp.o",
				"-lml", "-lcl", (char *) 0);
	}
	unlink ("tmpmkctmp.o");
	return rc;
}
#else /* ! AMIGA */
	fprintf (stderr, "hint: don't know how to compile the file...\n");
	return -1;
#endif /* ! AMIGA */
#endif /* ! unix */
}

/* end of util.c */
