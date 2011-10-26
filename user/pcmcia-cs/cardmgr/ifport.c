/*======================================================================

    Utility to select the transceiver type for a network device

    ifport.c 1.13 2000/06/12 21:33:02

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
    
======================================================================*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *if_names[] = {
    "Auto", "10baseT", "10base2", "AUI", "100baseT"
};
#define NR_NAMES (sizeof(if_names)/sizeof(char *))

/*====================================================================*/

static int sockets_open(void)
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) != -1)
	return sock;
    else if ((sock = socket(AF_IPX, SOCK_DGRAM, 0)) != -1)
	return sock;
    else if ((sock = socket(AF_AX25, SOCK_DGRAM, 0)) != -1)
	return sock;
    else
	return socket(AF_APPLETALK, SOCK_DGRAM, 0);
}

/*====================================================================*/

void usage(char *s)
{
    fprintf(stderr, "usage: %s interface "
	    "[auto|10baseT|10base2|aui|100baseT|##]\n", s);
    exit(1);
}

int main(int argc, char **argv)
{
    struct ifreq ifr;
    int i, skfd;

    if ((argc < 2) || (argc > 3))
	usage(argv[0]);
    skfd = sockets_open();
    if (skfd == -1) {
	perror("socket");
	exit(1);
    }
    strcpy(ifr.ifr_name, argv[1]);
    if (ioctl(skfd, SIOCGIFMAP, &ifr) < 0)
	fprintf(stderr, "%s: unknown interface.\n", argv[1]);
    else {
	if (argc == 2) {
	    printf("%s\t%d", argv[1], ifr.ifr_map.port);
	    if (ifr.ifr_map.port < NR_NAMES)
		printf(" (%s)\n", if_names[ifr.ifr_map.port]);
	    else
		printf("\n");
	}
	else {
	    for (i = 0; i < NR_NAMES; i++)
		if (strcasecmp(argv[2], if_names[i]) == 0)
		    break;
	    if (i < 5)
		ifr.ifr_map.port = i;
	    else {
		char *s;
		ifr.ifr_map.port = strtoul(argv[2], &s, 0);
		if ((s == argv[2]) || (*s != '\0'))
		    usage(argv[0]);
	    }
	    if (ioctl(skfd, SIOCSIFMAP, &ifr) < 0)
		perror("ioctl");
	}
    }
    close(skfd);
    exit(0);
    return 0;
}
