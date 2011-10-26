#ifndef		_UDP_H_
#define		_UDP_H_

#include	"ctypes.h"
#include	"smp.h"

SmpStatusType	udpSend (SmpSocketType udp, CBytePtrType bp, CIntfType n);
SmpSocketType	udpNew (int so, u_long host, u_short port);
SmpSocketType	udpFree (SmpSocketType udp);

#endif		/*	_UDP_H_	*/
