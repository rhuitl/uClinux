#ifndef lint
static char rcsid[] = "$Id: config.prim.c,v 1.13 1994/04/04 00:34:26 gkim Exp $";
#endif

/*
 * config.prim.c
 *
 *	process configuration file directive primitives (ala m4 or cpp).
 *
 *		ifhost
 *		define
 *		undef
 *		ifdef
 *		ifndef
 *
 * Gene Kim
 * Purdue University
 * September 28, 1992
 */

#include "../include/config.h"
#include <stdio.h>
#ifdef __STDC__
# include <sys/types.h>
# include <sys/stat.h>
#endif
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include "../include/tripwire.h"
#include "../include/list.h"
#include <ctype.h>
#include <sys/param.h>
#ifndef GETHOSTNAME
#include <sys/utsname.h>
#endif
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

static struct list *defines_table = (struct list *) NULL;

/*
 * void
 * tw_mac_define(char *varname, char *varvalue)
 *
 *	set (varname) to (varvalue) in the defines table
 */

void
tw_mac_define(varname, varvalue)
    char *varname, *varvalue;
{
    list_set(varname, varvalue, 0, &defines_table);
}

/* char *
 * tw_mac_dereference(char *varname)
 *
 *	returns the (varvalue) in the defines table.
 */

char *
tw_mac_dereference(varname)
    char *varname;
{
    return list_lookup(varname, &defines_table);
}

/*
 * void
 * tw_mac_undef(char *varname)
 *
 *	removes (varname) from the defines table.
 */

void
tw_mac_undef(varname)
    char *varname;
{
    list_unset(varname, &defines_table);
}

/*
 * int
 * tw_mac_ifdef(char *varname)
 *
 *	returns 1 if (varname) is in defines table, else 0.
 */

int
tw_mac_ifdef(varname)
    char *varname;
{
    return list_isthere(varname, &defines_table);
}

/*
 * int
 * tw_mac_ifhost(char *hostname)
 *
 *	returns 1 if (hostname) matches our hostname
 */

int
tw_mac_ifhost(hostname)
    char *hostname;
{
    char realhostname[MAXHOSTNAMELEN];
    register char *tc, *sc;

#ifndef GETHOSTNAME
    struct utsname sysinfo;

    if (uname(&sysinfo) < 0)
	die_with_err("filename_hostname_expand: uname()", (char *) NULL);

    (void) strncpy(realhostname, sysinfo.nodename, MAXHOSTNAMELEN);

#else 	/* GETHOSTNAME */

    /* get the hostname */
    if (gethostname(realhostname, MAXHOSTNAMELEN) < 0)
	die_with_err("filename_hostname_expand: gethostname()", (char *) NULL);


#endif 	/* GETHOSTNAME */

    /* check for a period in the hostname (only if there are periods in the
     * the real hostnames)
     */
    if (!strchr(hostname, '.') && strchr(realhostname, '.')) {
	fprintf(stderr, 
"warning: hostname in @@ifhost directives must be fully qualified!\n");
	fprintf(stderr, "\t\t(e.g. 'mentor.cc.purdue.edu')\n");
    }

    /* check for a match between the hostnames (case insensitive) */

    for (sc = realhostname, tc = hostname; *sc && *tc ; sc++, tc++) {
        if (*tc == *sc)
	  continue;
	else if (isupper(*tc) && islower(*sc)) {
	  if (tolower(*tc) != *sc)
	    return 0;
}
	else if (islower(*tc) && isupper(*sc)) {
	  if (*tc != tolower(*sc))
	    return 0;
        }
	else
	  return 0;
    }
    return (!(*tc || *sc));
}

