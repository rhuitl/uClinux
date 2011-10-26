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
 * err.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * here is only the a60_error () routine.
 */

#include "comm.h"


#ifdef VPRINTF_MISSING
/*
 * <no comment>
 */
#define USE_DUMB_A60_ERR
/*
 * this may not work on machines, with sizeof(int) != sizeof(long) !=
 * sizeof (char *) ...
 */
#endif


#ifndef USE_DUMB_A60_ERR

/*
 * use vprintf.
 */

#ifdef __STDC__
#include <stdarg.h>
extern vfprintf (FILE *, const char *, va_list);
#else /* ! __STDC__ */
#include <varargs.h>
extern vfprintf ();
#endif /* ! __STDC__ */

#include "a60.h"


/* VARARGS */
void
#ifdef __STDC__
a60_error (char *fname, int line, char *format, ...)
#else
a60_error (fname, line, format, va_alist)
char *fname;
int line;
char *format;
va_dcl
#endif
{
	va_list pvar;

	fprintf (stderr, "%s: %d: ", fname, line);

#ifdef __STDC__
	va_start (pvar, format);
#else
	va_start (pvar);
#endif
	vfprintf (stderr, format, pvar);
	va_end (pvar);
}

#else /* USE_DUMB_A60_ERR */

/*
 * the ugly one:
 */

void
a60_error (fname, line, format, p1, p2, p3, p4, p5, p6, p7, p8, p9)
char *fname;
int line;
char *format;
int p1, p2, p3, p4, p5, p6, p7, p8, p9;
{
	fprintf (stderr, "%s: %d: ", fname, line);
	fprintf (stderr, format, p1, p2, p3, p4, p5, p6, p7, p8, p9);
}

#endif /* USE_DUMB_A60_ERR */
