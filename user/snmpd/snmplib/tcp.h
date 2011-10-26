#ifndef		_TCP_H_
#define		_TCP_H_

#include	"ctypes.h"
#include	"smp.h"

SmpStatusType	tcpSend (SmpSocketType tcp, CBytePtrType cp, CIntfType n);
SmpSocketType	tcpNew (int so, char *host, u_short port);
SmpSocketType	tcpFree (SmpSocketType tcp);

#endif		/*	_TCP_H_	*/
