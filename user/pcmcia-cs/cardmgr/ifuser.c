/*======================================================================

    This utility checks to see if any of a list of hosts or network
    addresses are routed through a specified interface.  Destinations
    may be specified either by IP address or by name.
    
    usage: ifuser [-v] interface [target ...]

    The exit code is 0 if any host is using the specified interface,
    and 1 if the interface is not in use (just like fuser).
    
    ifuser.c 1.15 2000/06/12 21:33:02

    1998/10/24: Regis "HPReg" Duchesne <regis@via.ecp.fr>
      . Added network names (/etc/networks) management
      . Used u_int32_t instead of u_int
      . Handled a malloc error

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is David A. Hinds
    <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
    are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.

    Alternatively, the contents of this file may be used under the
    terms of the GNU Public License version 2 (the "GPL"), in which
    case the provisions of the GPL are applicable instead of the
    above.  If you wish to allow the use of your version of this file
    only under the terms of the GPL and not to allow others to use
    your version of this file under the MPL, indicate your decision
    by deleting the provisions above and replace them with the notice
    and other provisions required by the GPL.  If you do not delete
    the provisions above, a recipient may use your version of this
    file under either the MPL or the GPL.
    Portions created by Regis "HPReg" Duchesne are Copyright (C) 1998
    Regis "HPReg" Duchesne.  All Rights Reserved.

======================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct route_t {
    u_int32_t		dest, mask;
    int			match;
    struct route_t	*next;
} route_t;

/*====================================================================*/

static int resolv_name(char *s, u_int32_t *a)
{
    struct in_addr addr;
    struct hostent *hp;
    struct netent *np;
    
    if (inet_aton(s, &addr)) {
	*a = (u_int32_t)ntohl(addr.s_addr);
	return 0;
    }
    np = getnetbyname(s);
    if (np) {
	*a = (u_int32_t)np->n_net;
	return 0;
    }
    hp = gethostbyname(s);
    if (hp) {
	*a = (u_int32_t)ntohl(*(u_int32_t *)hp->h_addr_list[0]);
	return 0;
    }
    return -1;
}

/*====================================================================*/

static void usage(char *s)
{
    fprintf(stderr, "usage: %s [-v] interface [target ...]\n", s);
    exit(1);
}

int main(int argc, char *argv[])
{
    char *dev, s[129], dest[16], mask[16], iface[10];
    route_t *r, *tbl, **tail;
    int i, verbose = 0, busy = 0;
    FILE *f;

    i = 1;
    if (argc < 2) usage(argv[0]);
    if (strcmp(argv[1], "-v") == 0) {
	verbose = 1; i++;
    }
    if ((*argv[i] == '-') || (argc < i+1)) usage(argv[0]);
    dev = argv[i]; i++;
    
    /* Get routing table */
    f = popen("netstat -nr", "r");
    if (f == NULL) {
	fprintf(stderr, "%s: could not get routing table: %s\n",
		argv[0], strerror(errno));
	return 2;
    }
    
    do {
	fgets(s, 128, f);
    } while (!feof(f) && !isdigit(s[0]));
    
    tail = &tbl;
    do {
	r = malloc(sizeof(route_t));
	if (r == NULL) {
	    fprintf(stderr, "%s: out of memory\n", argv[0]);
	    return 2;
	}
	sscanf(s, "%s %*s %s %*s %*s %*s %*s %s", dest, mask, iface);
	resolv_name(dest, &r->dest);
	resolv_name(mask, &r->mask);
	r->match = (strcmp(iface, dev) == 0);
	*tail = r; tail = &(r->next);
    } while (fgets(s, 128, f) != NULL);
    *tail = NULL;
    pclose(f);

    /* Check each host on command line */
    for (; i < argc; i++) {
	u_int32_t a;
	if (resolv_name(argv[i], &a) != 0) {
	    fprintf(stderr, "%s: lookup failed: %s\n",
		    argv[0], argv[i]);
	    continue;
	}

	for (r = tbl; r; r = r->next) {
	    if ((a & r->mask) == r->dest) {
		if (r->match) {
		    if (verbose) {
			if (!busy) printf("%s:", dev);
			printf(" %s", argv[i]);
		    }
		    busy = 1;
		}
		break;
	    }
	}
    }
    
    if (busy && verbose)
	printf("\n");
    return (!busy);
}
