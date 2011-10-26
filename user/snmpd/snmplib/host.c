#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<netdb.h>
#include	<stdio.h>

#include	"local.h"
#include	"host.h"

long		hostAddress (char *string)
{
	struct		hostent		*hp;
	long		host;

	host = (long) inet_addr (string);
	if (host == -1L) {
		hp = gethostbyname (string);
		if (hp == NULL) {
			return (-1);
		}
		else if (hp->h_addrtype != AF_INET) {
			return (-1);
		}
		else {
			host = 0L;
			bcopy (hp->h_addr, (char *) & host,
				sizeof (host));
		}
	}
	return (host);
}

int		hostString (char *result, int n, long int host)
{
	struct		hostent		*hp;
	struct		in_addr		in;
	int				k;
	char				*cp;

	hp = gethostbyaddr ((char *) & host, (int) sizeof (host),(int) AF_INET);
	if (hp != NULL) {
		k = strlen (hp->h_name);
		if (k > n) {
			return (0);
		}
		else {
			(void) strcpy (result, hp->h_name);
			return (k);
		}
	}
	else {
		(void) bzero ((char *) & in, (int) sizeof (in));
		in.s_addr = (u_long) host;
		cp = inet_ntoa (in);
		if (cp == (char *) NULL) {
			return (0);
		}
		else if ((k = strlen (cp)) > n) {
			return (0);
		}
		else {
			(void) strcpy (result, cp);
			return (k);
		}
	}
}

