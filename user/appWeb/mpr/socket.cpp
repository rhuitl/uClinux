///
///	@file 	socket.cpp
/// @brief 	Convenience class for the management of sockets
///
///	This module provides a higher level C++ interface to interact with the 
///	standard sockets API. It does not perform buffering.
///
///	This modules is thread-safe.
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This software is open source; you can redistribute it and/or modify it 
//	under the terms of the GNU General Public License as published by the 
//	Free Software Foundation; either version 2 of the License, or (at your 
//	option) any later version.
//
//	This program is distributed WITHOUT ANY WARRANTY; without even the 
//	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
//	See the GNU General Public License for more details at:
//	http://www.mbedthis.com/downloads/gplLicense.html
//	
//	This General Public License does NOT permit incorporating this software 
//	into proprietary programs. If you are unable to comply with the GPL, a 
//	commercial license for this software and support services are available
//	from Mbedthis Software at http://www.mbedthis.com
//
/////////////////////////////////// Includes ///////////////////////////////////

#define 	IN_MPR	1

#include	"mpr.h"

////////////////////////////////////////////////////////////////////////////////

static void ioProcWrapper(void *data, int mask, int isMprPoolThread);
static void acceptProcWrapper(void *data, int mask, int isMprPoolThread);

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MprSocketService ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Open socket service
//

MprSocketService::MprSocketService()
{
#if BLD_FEATURE_LOG
	log = new MprLogModule("socket");
#endif

#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Close the socket service
//

MprSocketService::~MprSocketService()
{
	MprInterface	*ip, *nextIp;

#if BLD_DEBUG
	if (socketList.getNumItems() > 0) {
		MprSocket	*sp;
		mprError(MPR_L, MPR_LOG, "Exiting with %d sockets unfreed\n",
			socketList.getNumItems());
		sp = (MprSocket*) socketList.getFirst();
		while (sp) {
			mprLog(2, "~MprSocketService: open socket %d, sp %x\n", 
				sp->getFd(), sp);
			sp = (MprSocket*) socketList.getNext(sp);
		}
	}
#endif

	ip = (MprInterface*) ipList.getFirst();
	while (ip) {
		nextIp = (MprInterface*) ipList.getNext(ip);
		ipList.remove(ip);
		delete ip;
		ip = nextIp;
	}
	delete log;
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start the socket service
//

int MprSocketService::start()
{
	char	hostName[MPR_MAX_IP_NAME];
	char	serverName[MPR_MAX_IP_NAME];
	char	domainName[MPR_MAX_IP_NAME];
	char	*dp;

	serverName[0] = '\0';
	domainName[0] = '\0';
	hostName[0] = '\0';

	if (gethostname(serverName, sizeof(serverName)) < 0) {
		mprStrcpy(serverName, sizeof(serverName), "localhost");
		mprError(MPR_L, MPR_USER, "Can't get host name");
		// Keep going
	}
	if ((dp = strchr(serverName, '.')) != 0) {
		mprStrcpy(hostName, sizeof(hostName), serverName);
		*dp++ = '\0';
		mprStrcpy(domainName, sizeof(domainName), dp);
	} else {
		mprStrcpy(hostName, sizeof(hostName), serverName);
	}

	lock();
	mpr->setServerName(serverName);
	mpr->setDomainName(domainName);
	mpr->setHostName(hostName);

	getInterfaces();
	unlock();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Stop the socket service. Must be idempotent.
//

int MprSocketService::stop()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Add a socket to the socket list
//

void MprSocketService::insertMprSocket(MprSocket *sp)
{
	lock();
	socketList.insert(sp); 
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Remove a socket from the socket list
//

void MprSocketService::removeMprSocket(MprSocket *sp) 
{
	lock();
	socketList.remove(sp); 
	unlock();
}

////////////////////////////////////////////////////////////////////////////////

int MprSocketService::getInterfaces()
{
#if LINUX || MACOSX
    struct sockaddr_in	addr, bcast, mask;
	struct ifreq		*ifrp, *endp;
	struct ifconf		ifc;
	char				addrStr[MPR_MAX_IP_ADDR], bcastStr[MPR_MAX_IP_ADDR];
	char				maskStr[MPR_MAX_IP_ADDR];
	int					sock;

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	ifc.ifc_len = 16 * sizeof(struct ifreq);
	ifc.ifc_buf = (char*) new struct ifreq [16];
	if (ioctl(sock, SIOCGIFCONF, (int) &ifc) < 0) {
		mprAssert(0);
		return MPR_ERR_CANT_OPEN;
	}

	ifrp = (struct ifreq*) ifc.ifc_buf;
	endp = (struct ifreq*) (&ifc.ifc_buf[ifc.ifc_len]);
	for (; ifrp < endp; ifrp++) {

		if (ioctl(sock, SIOCGIFADDR, (int) ifrp) < 0) {
			mprAssert(0);
			continue;
		}
		memcpy(&addr, &ifrp->ifr_addr, sizeof(struct sockaddr));
		mprInetNtoa(addrStr, sizeof(addrStr), addr.sin_addr);

		if (ioctl(sock, SIOCGIFBRDADDR, (int) ifrp) < 0) {
			mprAssert(0);
		}
		memcpy(&bcast, &ifrp->ifr_broadaddr, sizeof(struct sockaddr));
		mprInetNtoa(bcastStr, sizeof(bcastStr), bcast.sin_addr);

		if (ioctl(sock, SIOCGIFNETMASK, (int) ifrp) < 0) {
			mprAssert(0);
		}
		memcpy(&mask, &ifrp->ifr_addr, sizeof(struct sockaddr));
		mprInetNtoa(maskStr, sizeof(maskStr), mask.sin_addr);

		ipList.insert(new MprInterface(addrStr, bcastStr, maskStr));
	}
	//	loopback = htonl(0x7F000000) & mask; 
	delete ifc.ifc_buf;
#endif
#if WIN
	struct hostent		*hp;
	char				addrStr[MPR_MAX_IP_ADDR];

	hp = mprGetHostByName(mpr->getServerName());
	if (hp == 0) {
		mprError(MPR_L, MPR_USER, "Can't get IP address for this server");

	} else {
		for (int i = 0; hp->h_addr_list[i]; i++) {
			mprInetNtoa(addrStr, sizeof(addrStr), 
				*((struct in_addr*) hp->h_addr_list[i]));
			ipList.insert(new MprInterface(addrStr, 0, 0));
		}
		ipList.insert(new MprInterface("127.0.0.1", 0, 0));
	}
	mprFreeGetHostByName(hp);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return a pointer to the IP address list. Caller must not modify !!!!!
//

MprList *MprSocketService::getInterfaceList()
{
	return &ipList;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MprSocket ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Allocate a socket class
//

MprSocket::MprSocket()
{
	acceptCallback = 0;
	callbackData = 0;
	currentEvents = 0;
	error = 0;
	flags = 0;
	handler = 0;
	handlerMask = 0;
	handlerPriority = MPR_NORMAL_PRIORITY;
	interestEvents = 0;
	inUse = 0;
	ioCallback = 0;
	ipAddr = 0;
	port = -1;
	secure = 0;
	selectEvents = 0;
	sock = -1;

#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif

#if BLD_FEATURE_LOG
	log = mpr->socketService->getLogModule();
	mprLog(7, log, "0: new MprSocket\n");
#endif

	mpr->socketService->insertMprSocket(this);
}

////////////////////////////////////////////////////////////////////////////////

bool MprSocket::dispose()
{
	lock();
	if (!(flags & MPR_SOCKET_DISPOSED)) {
		if (handler) {
			handler->dispose();
			handler = 0;
		}
	}
	flags |= MPR_SOCKET_DISPOSED;
	mprLog(8, log, "dispose: inUse %d\n", inUse);
	if (inUse == 0) {
		delete this;
	} else {
		unlock();
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Destroy a socket
//

MprSocket::~MprSocket()
{
	lock();
	mprLog(8, log, "~MprSocket: Destroying\n");
	if (sock >= 0) {
		mprLog(7, log, "%d: ~MprSocket: closing %x\n", sock);
		this->close(MPR_SHUTDOWN_BOTH);
		sock = 0;
	}
	mpr->socketService->removeMprSocket(this);
	if (ipAddr) {
		mprFree(ipAddr);
		ipAddr = 0;
	}
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

MprSocket *MprSocket::newSocket()
{
	return new MprSocket();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Open a server socket connection
//

int MprSocket::openServer(char *addr, int portNum, 
	MprSocketAcceptProc acceptFn, void *data, int initialFlags)
{
	struct sockaddr_in	sockAddr;
	int					datagram, rc;

	mprLog(6, log, "openServer: %s:%d, flags %x\n", addr, portNum, 
		initialFlags);

	memset((char *) &sockAddr, '\0', sizeof(struct sockaddr_in));
	sockAddr.sin_family = AF_INET;

	lock();
	port = portNum;
	acceptCallback = acceptFn;
	callbackData = data;
	flags = (initialFlags & 
		(MPR_SOCKET_BROADCAST | MPR_SOCKET_DATAGRAM | MPR_SOCKET_BLOCK | 
		 MPR_SOCKET_LISTENER | MPR_SOCKET_NOREUSE | MPR_SOCKET_NODELAY));
	ipAddr = mprStrdup(addr);

	sockAddr.sin_port = htons((short) (port & 0xFFFF));
	if (strcmp(ipAddr, "") != 0) {
		sockAddr.sin_addr.s_addr = inet_addr(ipAddr);
	} else {
		sockAddr.sin_addr.s_addr = INADDR_ANY;
	}

	datagram = flags & MPR_SOCKET_DATAGRAM;

	//
	//	Create the O/S socket
	//
	sock = socket(AF_INET, datagram ? SOCK_DGRAM: SOCK_STREAM, 0);
	if (sock < 0) {
		unlock();
		return MPR_ERR_CANT_OPEN;
	}
#if !WIN
	fcntl(sock, F_SETFD, FD_CLOEXEC);		// Children won't inherit this fd
#endif

#if LINUX
	if (!(flags & MPR_SOCKET_NOREUSE)) {
		rc = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &rc, sizeof(rc));
	}
#endif

	rc = bind(sock, (struct sockaddr *) &sockAddr, sizeof(sockAddr));
	if (rc < 0) {
		::closesocket(sock);
		sock = -1;
		unlock();
		return MPR_ERR_CANT_OPEN;
	}

	if (! datagram) {
		flags |= MPR_SOCKET_LISTENER;
		if (listen(sock, 15) < 0) {
			::closesocket(sock);
			sock = -1;
			unlock();
			return MPR_ERR_CANT_OPEN;
		}
		handler = new MprSelectHandler(sock, MPR_SOCKET_READABLE, 
			(MprSelectProc) acceptProcWrapper, (void*) this, handlerPriority);
	}
	handlerMask |= MPR_SOCKET_READABLE;

#if WIN
	//
	//	Delay setting reuse until now so that we can be assured that we
	//	have exclusive use of the port.
	//
	if (!(flags & MPR_SOCKET_NOREUSE)) {
		rc = 1;
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*) &rc, sizeof(rc));
	}
#endif

	setBlockingMode((bool) (flags & MPR_SOCKET_BLOCK));

	//
	//	TCP/IP stacks have the No delay option (nagle algorithm) on by default.
	//
	if (flags & MPR_SOCKET_NODELAY) {
		setNoDelay(1);
	}
	unlock();
	return sock;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Open a client socket connection
//

int MprSocket::openClient(char *addr, int portNum, int initialFlags)
{
	struct sockaddr_in	remoteAddr;
	struct hostent		*hostent;
	int					broadcast, datagram, rc, err;

	mprLog(6, log, "openClient: %s:%d, flags %x\n", addr, portNum, 
		initialFlags);

	memset((char *) &remoteAddr, '\0', sizeof(struct sockaddr_in));
	remoteAddr.sin_family = AF_INET;

	lock();
	port = portNum;
	flags = (initialFlags & 
		(MPR_SOCKET_BROADCAST | MPR_SOCKET_DATAGRAM | MPR_SOCKET_BLOCK | 
		 MPR_SOCKET_LISTENER | MPR_SOCKET_NOREUSE | MPR_SOCKET_NODELAY));
	ipAddr = mprStrdup(addr);

	remoteAddr.sin_port = htons((short) (port & 0xFFFF));
	remoteAddr.sin_addr.s_addr = inet_addr(ipAddr);
	if (remoteAddr.sin_addr.s_addr == INADDR_NONE) {
		hostent = mprGetHostByName(ipAddr);
		if (hostent != 0) {
			memcpy((char*) &remoteAddr.sin_addr, 
				(char*) hostent->h_addr_list[0], (size_t) hostent->h_length);
			mprFreeGetHostByName(hostent);
		} else {
			unlock();
			return MPR_ERR_NOT_FOUND;
		}
	}

	broadcast = flags & MPR_SOCKET_BROADCAST;
	if (broadcast) {
		flags |= MPR_SOCKET_DATAGRAM;
	}
	datagram = flags & MPR_SOCKET_DATAGRAM;

	//
	//	Create the O/S socket
	//
	sock = socket(AF_INET, datagram ? SOCK_DGRAM: SOCK_STREAM, 0);
	if (sock < 0) {
		err = getError();
		unlock();
		return -err;
	}
#if !WIN
	fcntl(sock, F_SETFD, FD_CLOEXEC);		// Children won't inherit this fd
#endif

	if (broadcast) {
		int	flag = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *) &flag,
				sizeof(flag)) < 0) {
			err = getError();
			::closesocket(sock);
			sock = -1;
			unlock();
			return -err;
		}
	}
 
	if (!datagram) {
		flags |= MPR_SOCKET_CONNECTING;
		rc = connect(sock, (struct sockaddr *) &remoteAddr, sizeof(remoteAddr));
		if (rc < 0) {
			err = getError();
			::closesocket(sock);
			sock = -1;
			unlock();
#if UNUSED
			//
			//	If the listen backlog is too high, ECONNREFUSED is returned
			//
			if (err == EADDRINUSE || err == ECONNREFUSED) {
				return MPR_ERR_BUSY;
			}
#endif
			return -err;
		}
	}

	setBlockingMode((bool) (flags & MPR_SOCKET_BLOCK));

	//
	//	TCP/IP stacks have the No delay option (nagle algorithm) on by default.
	//
	if (flags & MPR_SOCKET_NODELAY) {
		setNoDelay(1);
	}
	unlock();
	return sock;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Close a socket (gracefully)
//

void MprSocket::close(int how)
{
	MprSelectService	*ss;
	char				buf[1024];
	int					handlerFlags;

	mprLog(7, log, "%d: close\n", sock);
	ss = mpr->selectService;

	lock();
	mprAssert(!(flags & MPR_SOCKET_CLOSED));
	if (flags & MPR_SOCKET_CLOSED) {
		unlock();
		return;
	}
	flags |= MPR_SOCKET_CLOSED;
	handlerFlags = (handler) ? handler->getFlags() : 0;

	if (handler) {
		handler->dispose();
		handler = 0;
	}

	if (sock >= 0) {
		//
		//	Do a graceful shutdown. Read any outstanding read data to prevent
		//	resets. Then do a shutdown to send a FIN and read outstanding 
		//	data. All non-blocking.
		//
#if WIN
		if (ss->getFlags() & MPR_ASYNC_SELECT) {

			if (handlerFlags & MPR_SELECT_CLIENT_CLOSED) {
				//
				//	Client initiated close. We have already received an FD_CLOSE
				//
				closesocket(sock);
				sock = -1;

			} else {
				//
				//	Do a graceful shutdown. Read any outstanding read data to 
				//	prevent resets. Then do a shutdown to send a FIN and lastly
				//	read data when the FD_CLOSE is received (see select.cpp). 
				//	All done non-blocking.
				//
				setBlockingMode(0);
				while (recv(sock, buf, sizeof(buf), 0) > 0) {
					;
				}

				//
				//	Delayed close call must be first so we are ready when the
				//	FD_CLOSE arrives. Other way round and there is a race if 
				//	multi-threaded. 
				//
				ss->delayedClose(sock);
				shutdown(sock, how);

				//
				//	We need to ensure we receive an FD_CLOSE to complete the
				//	delayed close. Despite disposing the hander above, socket 
				//	messages will still be sent from windows and so select can 
				//	cleanup the delayed close socket.
				//
				WSAAsyncSelect(sock, ss->getHwnd(), ss->getMessage(), FD_CLOSE);
			}
		
		} else {
#endif
			setBlockingMode(0);
			while (recv(sock, buf, sizeof(buf), 0) > 0) {
				;
			}
			if (shutdown(sock, how) >= 0) {
				while (recv(sock, buf, sizeof(buf), 0) > 0) {
					;
				}
			}

			//
			//	Use delayed close to prevent anyone else reusing the socket
			//	while select has not fully cleaned it out of its masks.
			//
			ss->delayedClose(sock);
			ss->awaken(0);
		}
#if WIN
	}
#endif

	//
	//	Re-initialize all socket variables so the Socket can be reused.
	//
	acceptCallback = 0;
	callbackData = 0;
	selectEvents = 0;
	currentEvents = 0;
	error = 0;
	flags = MPR_SOCKET_CLOSED;
	ioCallback = 0;
	handlerMask = 0;
	handlerPriority = MPR_NORMAL_PRIORITY;
	interestEvents = 0;
	port = -1;
	sock = -1;
	if (ipAddr) {
		mprFree(ipAddr);
		ipAddr = 0;
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Forcibly close a socket. Used to unblock a blocking read / write.
//

void MprSocket::forcedClose()
{
	mprLog(6, log, "%d: forcedClose\n", sock);

	//
	//	Delay calling lock until we call close() below as we wan't to ensure
	//	we don't block before we get to call close.
	//
	lock();
	if (sock >= 0) {
#if LINUX || MACOSX
		shutdown(sock, MPR_SHUTDOWN_BOTH);
#endif
		::closesocket(sock);
		sock = -1;
		this->close(MPR_SHUTDOWN_BOTH);
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Accept handler. May be called directly if single-threaded or on a pool
//	thread.
//

static void acceptProcWrapper(void *data, int mask, int isMprPoolThread)
{
	MprSocket		*sp;

	sp = (MprSocket*) data;
	sp->acceptProc(isMprPoolThread);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Accept an incoming connection. (private)
//

void MprSocket::acceptProc(int isMprPoolThread)
{
	MprSocket			*nsp;
	struct sockaddr_in	addr;
	socklen_t			len;
	char				callerIpAddr[MPR_MAX_IP_ADDR];
	int					fd;

	if (acceptCallback == 0) {
		return;
	}
	lock();
	len = sizeof(struct sockaddr_in);
	fd = accept(sock, (struct sockaddr *) &addr, (socklen_t*) &len);
	if (fd < 0) {
		mprLog(6, log, "%d: acceptProc: accept failed %d\n", sock, getError());
		unlock();
		return;
	}
#if !WIN
	fcntl(fd, F_SETFD, FD_CLOEXEC);		// Prevent children inheriting
#endif

	nsp = newSocket();

	nsp->lock();
	nsp->sock = fd;
	nsp->ipAddr = mprStrdup(ipAddr);
	nsp->callbackData = callbackData;
	nsp->port = port;
	nsp->acceptCallback = acceptCallback;
	nsp->flags = flags;
	nsp->flags &= ~MPR_SOCKET_LISTENER;

	nsp->setBlockingMode((nsp->flags & MPR_SOCKET_BLOCK) ? 1: 0);

	if (nsp->flags & MPR_SOCKET_NODELAY) {
		nsp->setNoDelay(1);
	}
	nsp->inUse++;
	mprLog(6, log, "%d: acceptProc: isMprPoolThread %d, newSock %d\n", sock, 
		isMprPoolThread, fd);

	nsp->unlock();

	//
	//	Call the user accept callback.
	//
	mprInetNtoa(callerIpAddr, sizeof(callerIpAddr), addr.sin_addr);
	(nsp->acceptCallback)(nsp->callbackData, nsp, callerIpAddr, 
			ntohs(addr.sin_port), this, isMprPoolThread);

	nsp->lock();
	if (--nsp->inUse == 0 && nsp->flags & MPR_SOCKET_DISPOSED) {
		mprLog(9, log, "%d: acceptProc: Leaving deleted\n", sock);
		delete nsp;
	} else{
		nsp->unlock();
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Write data. Return the number of bytes written or -1 on errors.
//	NOTE: this routine will return with a short write if the underlying socket
//	can't accept any more data.
//

int	MprSocket::write(char *buf, int bufsize)
{
	struct sockaddr_in	server;
	int					sofar, errCode, len, written;

	mprAssert(buf);
	mprAssert(bufsize >= 0);
	mprAssert((flags & MPR_SOCKET_CLOSED) == 0);

	lock();

	if (flags & MPR_SOCKET_EOF) {
		sofar = bufsize;
	} else {
		errCode = 0;
		len = bufsize;
		sofar = 0;
		while (len > 0) {
			if ((flags & MPR_SOCKET_BROADCAST) || 
					(flags & MPR_SOCKET_DATAGRAM)) {
				server.sin_family = AF_INET;
				if (strcmp(ipAddr, "") != 0) {
					server.sin_addr.s_addr = inet_addr(ipAddr);
				} else {
					server.sin_addr.s_addr = INADDR_BROADCAST;
				}
				server.sin_port = htons((short)(port & 0xFFFF));
				written = sendto(sock, &buf[sofar], len, MSG_NOSIGNAL,
					(struct sockaddr*) &server, sizeof(server));
			} else {
				written = send(sock, &buf[sofar], len, MSG_NOSIGNAL);
			}
			if (written < 0) {
				errCode = getError();
				if (errCode == EINTR) {
					mprLog(8, log, "%d: write: EINTR\n", sock);
					continue;
				} else if (errCode == EAGAIN) {
					mprLog(8, log, "%d: write: EAGAIN returning %d\n", 
						sock, sofar);
					unlock();
					return sofar;
				}
				mprLog(8, log, "%d: write: error %d\n", sock, -errCode);
				unlock();
				return -errCode;
			}
			len -= written;
			sofar += written;
		}
	}
	mprLog(8, log, "%d: write: %d bytes, ask %d, flags %x\n", 
		sock, sofar, bufsize, flags);
	unlock();
	return sofar;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Write a string.
//

int MprSocket::write(char *s)
{
	return this->write(s, strlen(s));
}

////////////////////////////////////////////////////////////////////////////////
//
//	Read data. Return zero for EOF or no data if in non-blocking mode. Return
//	-1 for errors. On success, return the number of bytes read. Use getEof()
//	to tell if we are EOF or just no data (in non-blocking mode).
//
 
int	MprSocket::read(char *buf, int bufsize)
{
	struct sockaddr_in	server;
	socklen_t			len;
	int					bytes, errCode;

	mprAssert(buf);
	mprAssert(bufsize > 0);
	mprAssert(~(flags & MPR_SOCKET_CLOSED));

	lock();

	if (flags & MPR_SOCKET_EOF) {
		unlock();
		return 0;
	}

again:
	if (flags & MPR_SOCKET_DATAGRAM) {
		len = sizeof(server);
		bytes = recvfrom(sock, buf, bufsize, MSG_NOSIGNAL,
			(struct sockaddr*) &server, (socklen_t*) &len);
	} else {
		bytes = recv(sock, buf, bufsize, MSG_NOSIGNAL);
	}

	if (bytes < 0) {
		errCode = getError();
		if (errCode == EINTR) {
			goto again;

		} else if (errCode == EAGAIN || errCode == EWOULDBLOCK) {
			bytes = 0;							// No data available

		} else if (errCode == ECONNRESET) {
			flags |= MPR_SOCKET_EOF;				// Disorderly disconnect
			bytes = 0;

		} else {
			flags |= MPR_SOCKET_EOF;				// Some other error
			bytes = -errCode;
		}

	} else if (bytes == 0) {					// EOF
		flags |= MPR_SOCKET_EOF;
		mprLog(8, log, "%d: read: %d bytes, EOF\n", sock, bytes);

	} else {
		mprLog(8, log, "%d: read: %d bytes\n", sock, bytes);
	}


	unlock();
	return bytes;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return true if end of file
//

bool MprSocket::getEof()
{
	bool	rc;

	lock();
	rc = ((flags & MPR_SOCKET_EOF) != 0);
	unlock();
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Define an IO callback for this socket. The callback called whenever there
//	is an event of interest as defined by handlerMask (MPR_SOCKET_READABLE, ...)
//

void MprSocket::setCallback(MprSocketIoProc fn, void *data, int mask, int pri)
{
	lock();
	ioCallback = fn;
	callbackData = data;
	handlerPriority = pri;
	handlerMask = mask;
	setMask(handlerMask);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the O/S socket file handle
//

int MprSocket::getFd()
{
	return sock;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the blocking mode of the socket
//

bool MprSocket::getBlockingMode()
{
	bool	rc;

	lock();
	rc = flags & MPR_SOCKET_BLOCK;
	unlock();
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the socket flags
//

int MprSocket::getFlags()
{
	int		rc;

	//
	//	These routines must still lock as the code will sometimes modify
	//	flags such that it can have invalid settings for a small window,
	//	see setBlockingMode() for an example.
	//
	lock();
	rc = flags;
	unlock();
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set whether the socket blocks or not on read/write
//

void MprSocket::setBlockingMode(bool on)
{
	int		flag;

	lock();
	mprLog(8, log, "%d: setBlockingMode: %d\n", sock, on);

	flags &= ~(MPR_SOCKET_BLOCK);
	if (on) {
		flags |= MPR_SOCKET_BLOCK;
	}

	flag = (flags & MPR_SOCKET_BLOCK) ? 0 : 1;
#if WIN
	ioctlsocket(sock, FIONBIO, (ulong*) &flag);
#else
	if (on) {
		fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK);
	} else {
		fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
	}
#endif
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Disable normal TCP delay behavior (nagle algorithm)
//

void MprSocket::setNoDelay(bool on)
{
	lock();
	if (on) {
		flags |= MPR_SOCKET_NODELAY;
	} else {
		flags &= ~(MPR_SOCKET_NODELAY);
	}
	{
#if WIN
		BOOL	noDelay;
		noDelay = on ? 1 : 0;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (FAR char *) &noDelay, 
			sizeof(BOOL));
#else
		int		noDelay;
		noDelay = on ? 1 : 0;
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &noDelay, 
			sizeof(int));
#endif // WIN 
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
#if WIN
#define OPT_CAST const char*
#else
#define OPT_CAST void*
#endif

int MprSocket::setBufSize(int sendSize, int recvSize)
{
	if (sock < 0) {
		return MPR_ERR_BAD_STATE;
	}
	if (sendSize > 0) {
		if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (OPT_CAST) &sendSize, 
				sizeof(int)) == -1) {
			return MPR_ERR_CANT_INITIALIZE;
		}
	}
	if (recvSize > 0) {
		if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (OPT_CAST) &recvSize, 
				sizeof(int)) == -1) {
			return MPR_ERR_CANT_INITIALIZE;
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the port number
//
 
int MprSocket::getPort()
{
	return port;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Select handler. May be called directly if single-threaded or on a pool
//	thread. User may call dispose() on the socket in the callback. This will
//	just mark it for deletion.
//

static void ioProcWrapper(void *data, int mask, int isMprPoolThread)
{
	MprSocket			*sp;

	sp = (MprSocket*) data;
	sp->ioProc(mask, isMprPoolThread);
}

////////////////////////////////////////////////////////////////////////////////

void MprSocket::ioProc(int mask, int isMprPoolThread)
{
	mprLog(7, log, "%d: ioProc: %x, mask %x\n", sock, callbackData, mask);

	lock();
	if (ioCallback == 0 || (handlerMask & mask) == 0) {
		unlock();
		mprLog(7, log, "%d: ioProc: returning, ioCallback %x, mask %x\n", 
			sock, ioCallback, mask);
		return;
	}
	mask &= handlerMask;
	mprLog(8, log, "%d: ioProc: %x, mask %x\n", sock, callbackData, mask);
	inUse++;
	unlock();

	(ioCallback)(callbackData, this, mask, isMprPoolThread);

	lock();
	if (--inUse == 0 && flags & MPR_SOCKET_DISPOSED) {
		mprLog(8, log, "%d: ioProc: Leaving deleted, inUse %d, flags %x\n", 
			sock, inUse, flags);
		delete this;
	} else {
		unlock();
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Define the events of interest. Must only be called with a locked socket.
//

void MprSocket::setMask(int handlerMask)
{
	lock();
	if (handlerMask) {
		if (handler) {
			handler->setInterest(handlerMask);
		} else {
			handler = new MprSelectHandler(sock, handlerMask,
				(MprSelectProc) ioProcWrapper, (void*) this, handlerPriority);
		}
	} else if (handler) {
		handler->setInterest(handlerMask);
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Map the O/S error code to portable error codes.
//

int MprSocket::getError()
{
#if WIN
	int		rc;
	switch (rc = WSAGetLastError()) {
	case WSAEINTR:
		return EINTR;

	case WSAENETDOWN:
		return ENETDOWN;

	case WSAEWOULDBLOCK:
		return EWOULDBLOCK;

	case WSAEPROCLIM:
		return EAGAIN;

	case WSAECONNRESET:
	case WSAECONNABORTED:
		return ECONNRESET;

	case WSAECONNREFUSED:
		return ECONNREFUSED;

	case WSAEADDRINUSE:
		return EADDRINUSE;
	default:
		return EINVAL;
	}
#else
	return errno;
#endif
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprInterface /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprInterface::MprInterface(char *ip, char *bcast, char *msk)
{
	mprAssert(ip);

	ipAddr = mprStrdup(ip);
	broadcast = mprStrdup(bcast);
	mask = mprStrdup(msk);
}

////////////////////////////////////////////////////////////////////////////////

MprInterface::~MprInterface()
{
	mprFree(ipAddr);
	mprFree(broadcast);
	mprFree(mask);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
extern "C" {
//
//	Replacement for gethostbyname that is multi-thread safe
//
//	FUTURE -- convention. Should take hostent as a parameter
//

struct hostent *mprGetHostByName(char *name)
{
	struct hostent	*ip;
	struct hostent	*hp;
	int				count, i;

	hp = new hostent;
	memset(hp, 0, sizeof(struct hostent));

	mpr->lock();

	#undef gethostbyname
	ip = gethostbyname(name);
	if (ip == 0) {
		mpr->unlock();
		return 0;
	}

	hp->h_addrtype = ip->h_addrtype;
	hp->h_length = ip->h_length;
	hp->h_name = mprStrdup(ip->h_name);
	hp->h_addr_list = 0;
	hp->h_aliases = 0;

	for (count = 0; ip->h_addr_list[count] != 0; ) {
		count++;
	}
	if (count > 0) {
		count++;
		hp->h_addr_list = new char*[count];
		for (i = 0; ip->h_addr_list[i] != 0; i++) {
			memcpy(&hp->h_addr_list[i], &ip->h_addr_list[i], ip->h_length);
		}
		hp->h_addr_list[i] = 0;
	}

	for (count = 0; ip->h_aliases[count] != 0; ) {
		count++;
	}
	if (count > 0) {
		count++;
		hp->h_aliases = new char*[count];
		for (i = 0; ip->h_aliases[i] != 0; i++) {
			hp->h_aliases[i] = mprStrdup(ip->h_aliases[i]);
		}
		hp->h_aliases[i] = 0;
	}
	mpr->unlock();
	return hp;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Free the allocated host entry structure 
//

void mprFreeGetHostByName(struct hostent *hostp)
{
	int	i;

	mprAssert(hostp);

	mprFree(hostp->h_name);

	if (hostp->h_addr_list) {
		delete[] hostp->h_addr_list;
	}

	if (hostp->h_aliases) {
		for (i = 0; hostp->h_aliases[i] != 0; i++) {
			mprFree(hostp->h_aliases[i]);
		}
		delete[] hostp->h_aliases;
	}
	delete hostp;
}

} // extern "C"
////////////////////////////////////////////////////////////////////////////////

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
