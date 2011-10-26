/* 	$Id: ip_masq_ioctl.c,v 0.3 1998/08/29 00:09:29 jjo Exp jjo $	 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/ip_masq.h>
#include "ipmasqadm.h"
#include "ipmasqctl.h"

int parse_addressport(const char * argv[], int argc, struct sockaddr_in *s_in, int no_lookup)
{
	int port;
	struct hostent *hent;
	struct servent *sent;
	char *p;

	if (argc < 1)
		return 0;
	if (inet_aton(argv[0],  &s_in->sin_addr)==0) {
		if (no_lookup)
			return -1;
		hent = gethostbyname (argv[0]);
		if (!hent) {
			herror(argv[0]);
			return -1;
		}
		if (hent->h_addrtype != AF_INET || hent->h_length != sizeof (struct in_addr)) {
			fprintf(stderr, "Invalid addr returned for \"%s\"\n", argv[0]);
			return -1;
		}
		memcpy(&s_in->sin_addr, hent->h_addr_list[0], sizeof(struct in_addr));
	}

	if (argc < 2) 
		return 1;

	port = strtoul(argv[1],&p,10);
	if (p>argv[1]) 
		port = htons(port);
	else {
		if (no_lookup)
			return 1;
		if (!(sent = getservbyname(argv[1],"tcp")) && 
				!(sent = getservbyname(argv[1],"udp")))
			return 1;
		port = sent->s_port;
	}

	s_in->sin_port = port;
#if 0
	printf("parsed %s %d\n", inet_ntoa(s_in->sin_addr), ntohs(s_in->sin_port));
#endif
	return 2;
}

char * addr_to_name(u_int32_t addr, char *name, int namelen, int nolookup)
{
	struct hostent *hent = NULL;

	if (!nolookup) {
		hent = gethostbyaddr((char*) &addr, sizeof(addr), AF_INET);
		if (hent) 
			strncpy(name, hent->h_name, namelen);
	}
	if (!hent)
		strncpy(name, inet_ntoa(*((struct in_addr*)&addr)), namelen);
	return name;
}

char * serv_to_name(u_int16_t serv, char *name, int namelen, int nolookup)
{
	struct servent *sent = NULL;

	if (!nolookup) {
		sent = getservbyport(serv, "tcp");
		if (sent) 
			strncpy(name, sent->s_name, namelen);
	}
	if (!sent)
		sprintf(name, "%d", ntohs(serv));
	return name;
}
