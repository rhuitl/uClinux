

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<stdio.h>

#include	"ctypes.h"
#include	"debug.h"
#include	"local.h"
#include	"udp.h"

typedef		struct			UdpTag {

		int			udpSocket;
		struct	sockaddr	udpSockAddr;
		CIntfType		udpRefCnt;

		}			UdpType;

typedef		UdpType		*UdpPtrType;

SmpStatusType	udpSend (SmpSocketType udp, CBytePtrType bp, CIntfType n)
{
	UdpPtrType		tp;
	int			result;

	if (udp == (SmpSocketType) 0) {
		return (errBad);
	}

	DEBUG0 ("udpSend:\n");
	DEBUGBYTES (bp, n);
	DEBUG0 ("\n");

	tp = (UdpPtrType) udp;
	do {	
		result = sendto (tp->udpSocket, (char *) bp,
			(int) n, (int) 0,
			& (tp->udpSockAddr), sizeof (struct sockaddr_in));
		n -= result;
		bp += result;

	} while ((result > 0) && (n > 0));

	if (result < 0) {
		perror ("udpSend");
		return (errBad);
	}
	else {
		return (errOk);
	}
}

SmpSocketType	udpNew (int so, u_long host, u_short port)
{
	UdpPtrType		tp;
	struct	sockaddr_in	*sin;

	tp = (UdpPtrType) malloc ((unsigned) sizeof (*tp));
	if (tp != (UdpPtrType) 0) {
		(void) bzero ((char *) tp, (int) sizeof (*tp));
		tp->udpSocket = so;
		tp->udpRefCnt = 1;
		sin = (struct sockaddr_in *) & tp->udpSockAddr;
		sin->sin_family = AF_INET;
		sin->sin_port = port;
		sin->sin_addr.s_addr = host;
	}

	return ((SmpSocketType) tp);
}

SmpSocketType	udpFree (SmpSocketType udp)
{
	UdpPtrType		tp;

	if (udp != (SmpSocketType) 0) {
		tp = (UdpPtrType) udp;
		if (--tp->udpRefCnt <= 0) {
			(void) free ((char *) tp);
		}
	}
	return ((SmpSocketType) 0);
}

