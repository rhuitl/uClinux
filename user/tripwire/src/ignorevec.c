#ifndef lint
static char     rcsid[] = "$Id: ignorevec.c,v 1.13 1994/07/15 11:03:44 gkim Exp $";
#endif

/*
 * ignorevec.c
 *
 *	ignore-flag vector handling routines
 *
 * Gene Kim
 * Purdue University
 */

#include "../include/config.h"
#include <stdio.h>
#ifdef STDLIBH
#include <stdlib.h>
#endif
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include <ctype.h>

#ifdef __STDC__			/* pick up all the structure prototypes */
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include "../include/list.h"
#include "../include/tripwire.h"

/*
 * ignore_vec_to_scalar(char *s)
 *
 *	take an ignore vector, and return an integer composed of OR'ed
 *	ignore flags.
 */

int
ignore_vec_to_scalar (s)
    char *s;
{
    register int  retval = 0;

    retval = (int) b64tol (s);

SPDEBUG (10)
printf ("ignore_vec_to_scalar (%s) --> %x\n", s, retval);

    return retval;
}

/*
 * ignore_configvec_to_dvec(char *s)
 *
 *	convert a configuration-style ignore vector to the format we use in
 *	database files.
 */

#define MASKIT(mask) if (ignorethis) {ignoremask |= (mask);} \
		     else {ignoremask = ignoremask & (~mask);}

void
ignore_configvec_to_dvec (s)
    char           *s;
{
    char dvec[128];
    int  ignoremask = 0, ignorethis = 0;
    char *pc;
    uint32 l;

    /*
     * where ignore-flags are in the format:
     *
     * 	[ [N|R|L]    [ [-|+][p|i|n|u|g|s|a|m|c|0|1|2|3|4|5|6|7|8|9] ] ]
     *	(template)     (modifier)
     *
     * Templates: 	(default)	N :  Nothing (+pinusgsamc0123456789)
     *				        R :  Read-only (N-a)
     *				        L :  Log (N-samc0123456789)
     *                                  E :  Everything (-pnugsamci0123456789)
     */


 /* walk through the ignore vector */
    for (pc = s; *pc; pc++) {

    /* look for template */
	switch (*pc) {
	case 'E':	 
	    ignoremask = IGNORE_P | IGNORE_N | IGNORE_U | IGNORE_G |
			 IGNORE_S | IGNORE_A | IGNORE_M | IGNORE_C |
			 IGNORE_I | IGNORE_0_9;
	    break;
	  case 'L':
	    ignoremask = IGNORE_S | IGNORE_A | IGNORE_M | IGNORE_C |
			 IGNORE_0_9;
	    break;
	  case 'N':
	    ignoremask = 0;
	    break;
	  case 'R':
	    ignoremask = IGNORE_A |
			 IGNORE_3 | IGNORE_4 | IGNORE_5 | IGNORE_6 |
			 IGNORE_7 | IGNORE_8 | IGNORE_9;
	    break;
	  case '>':
	    ignoremask = IGNORE_S | IGNORE_A | IGNORE_M | IGNORE_C |
			 IGNORE_0_9 |
			 IGNORE_GROW;
	    break;
	  default:
	    goto NEXTPLACE;
	}
    }
NEXTPLACE:
    for (; *pc; pc++) {
	switch (*pc) {
	  case '+': ignorethis = 0; break;
	  case '-': ignorethis = 1; break;
	  case 'p': MASKIT (IGNORE_P); break;
	  case 'i': MASKIT (IGNORE_I); break;
	  case 'n': MASKIT (IGNORE_N); break;
	  case 'u': MASKIT (IGNORE_U); break;
	  case 'g': MASKIT (IGNORE_G); break;
	  case 's': MASKIT (IGNORE_S); break;
	  case 'a': MASKIT (IGNORE_A); break;
	  case 'm': MASKIT (IGNORE_M); break;
	  case 'c': MASKIT (IGNORE_C); break;
	  case '0': MASKIT (IGNORE_0); break;
	  case '1': MASKIT (IGNORE_1); break;
	  case '2': MASKIT (IGNORE_2); break;
	  case '3': MASKIT (IGNORE_3); break;
	  case '4': MASKIT (IGNORE_4); break;
	  case '5': MASKIT (IGNORE_5); break;
	  case '6': MASKIT (IGNORE_6); break;
	  case '7': MASKIT (IGNORE_7); break;
	  case '8': MASKIT (IGNORE_8); break;
	  case '9': MASKIT (IGNORE_9); break;
	  default:
	    fprintf (stderr,
	     "%s: configuration parse error: illegal flag ('%c' in '%s')\n",
		     progname, *pc, s);
	    exit (1);
	}

    }

 /* now turn it into a string that we can interpolate */

    l = ignoremask;
    (void) pltob64 (&l, (char *) dvec, 1);

SPDEBUG (10)
printf ("ignore_configvec_to_dvec: (%s) --> (%s)\n", s, dvec);

    (void) strcpy (s, dvec);

    return;
}
