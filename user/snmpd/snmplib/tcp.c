

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<stdio.h>

#include	"ctypes.h"
#include	"debug.h"
#include	"tcp.h"

SmpStatusType	tcpSend (SmpSocketType tcp, CBytePtrType cp, CIntfType n)
{
	int			result;

	if (tcp == (SmpSocketType) 0) {
		return (errBad);
	}

	do {	

                result = send ((int) tcp,  (char *) cp,
                        (int) n, (int) 0);
                n -= result;
                cp += result;

	} while ((result > 0) && (n > 0));

	if (result < 0) {
		perror ("tcpSend");
		return (errBad);
	}
	else {
		return (errOk);
	}
}

SmpSocketType	tcpNew (int so, char *host, u_short port)
{
	host = host;
	port = port;
	return ((SmpSocketType) so);
}

SmpSocketType	tcpFree (SmpSocketType tcp)
{
	tcp = tcp;
	return ((SmpSocketType) 0);
}

