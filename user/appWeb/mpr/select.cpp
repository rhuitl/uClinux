///
///	@file 	select.cpp
/// @brief 	Management of socket select
///
///	This modules provides select management for sockets and allows
///	users to create IO handlers which will be called when IO events are 
///	detected. Windows uses a different message based mechanism. Unfortunately
///	while this module can (and has been run on Windows) -- performance is less
///	than stellar on windows and higher performance but not cross-platform
///	alternatives are used for windows.
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
////////////////////////////////// Includes ////////////////////////////////////

#define 	IN_MPR	1

#include	"mpr.h"

////////////////////////////// Forward Declarations ////////////////////////////

#if BLD_FEATURE_MULTITHREAD
static void selectProcWrapper(void *data, MprTask *tp);
#endif

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MprSelectService ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Initialize the select service
//

MprSelectService::MprSelectService()
{
	sock = -1;
	flags	= 0;
	rebuildMasks = 0;
	listGeneration = 0;
	maskGeneration = 0;
	maxDelayedFd = 0;
	port = MPR_DEFAULT_BREAK_PORT;				// Select breakout port

#if BLD_FEATURE_LOG
	log = new MprLogModule("select");
#endif

#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
	cond = new MprCond();
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Destroy the select service (users should have called stop() first)
//
 
MprSelectService::~MprSelectService()
{
#if BLD_FEATURE_MULTITHREAD
	lock();
	delete cond;
	delete mutex;
#endif

#if BLD_DEBUG
	if (list.getNumItems() > 0) {
		mprError(MPR_L, MPR_LOG, "Exiting with %d select handlers unfreed\n",
			list.getNumItems());
	}
#endif
#if BLD_FEATURE_LOG
	delete log;
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start the select service. Open a select breakout socket 
//

int MprSelectService::start()
{
	int		rc, retries;

	memset(&sa, 0, sizeof(sa));

	lock();
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");

	//
	//	Try to find a good port to use to breakout the select call
	// 
	for (retries = 0; retries < 10; retries++) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
#if !WIN
		fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
		sa.sin_port = htons((short)port);
		rc = bind(sock, (struct sockaddr *) &sa, sizeof(sa));
		if (sock >= 0 && rc == 0) {
			break;
		}
		if (sock >= 0) {
			closesocket(sock);
		}
		port++;
	}

	if (sock < 0 || rc < 0) {
		mprError(MPR_L, MPR_LOG, 
			"Can't open select select breakout port: %d, (errno %d.)\n",
			port, errno);
		unlock();
		return MPR_ERR_CANT_OPEN;
	}
	unlock();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Stop the select service. Must be idempotent.
//

int MprSelectService::stop()
{
	int		i;

#if BLD_FEATURE_LOG
	mprLog(8, log, "stop()\n");
#endif

	awaken(0);

	//
	//	Clear out delayed close fds
	//
	lock();
	for (i = 0; i < maxDelayedFd; i++) {
		if (delayedFds[i] >= 0) {
			closesocket(delayedFds[i]);
			delayedFds[i] = -1;
		}
	}
	maxDelayedFd = 0;
	unlock();

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Add a new handler
//

int MprSelectService::insertHandler(MprSelectHandler *sp)
{
	if (list.getNumItems() == FD_SETSIZE) {
		mprLog(MPR_INFO, log, "Too many select handlers: %d\n", FD_SETSIZE);
		return MPR_ERR_TOO_MANY;
	}

	lock();

#if BLD_DEBUG
	MprSelectHandler	*np;
	np = (MprSelectHandler*) list.getFirst();
	while (np) {
		if (sp->fd == np->fd) {
			mprAssert(sp->fd != np->fd);
			break;
		}
		np = (MprSelectHandler*) list.getNext(np);
	}
#endif

	mprLog(8, log, "%d: insertHandler\n", sp->fd);
	list.insert(sp);
	listGeneration++;
	maskGeneration++;

	unlock();
	awaken();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Remove a handler
//

void MprSelectService::removeHandler(MprSelectHandler *sp)
{
	lock();
	mprLog(8, log, "%d: removeHandler\n", sp->fd);
	list.remove(sp);
	listGeneration++;
	maskGeneration++;
	rebuildMasks++;
	unlock();
	awaken();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Modify a handler
//

int MprSelectService::modifyHandler(MprSelectHandler *sp, bool wakeUp)
{
	lock();
	mprLog(8, log, "%d: modifyHandler\n", sp->fd);
	maskGeneration++;
	unlock();
	if (wakeUp) {
		awaken();
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the file handles in use by all select handlers and define the
//	FD set masks. Called by the users main event loop in the users app.
//	Returns TRUE if the masks have changed.
//

int MprSelectService::getFds(fd_set *readInterest, fd_set *writeInterest, 
	fd_set *exceptInterest, int *maxFd, int *lastGet)
{
	MprSelectHandler	*sp;
	int					mask;

#if WIN
	if (flags & MPR_ASYNC_SELECT) {
		return MPR_ERR_BAD_STATE;
	}
#endif

	if (*lastGet == maskGeneration) {
		return 0;
	}

	if (rebuildMasks) {
		FD_ZERO(readInterest);
		FD_ZERO(writeInterest);
		FD_ZERO(exceptInterest);
	}

	*lastGet = maskGeneration;
	*maxFd = 0;

	mask = 0;
	lock();
	sp = (MprSelectHandler*) list.getFirst();
	while (sp) {
		mprAssert(sp->fd >= 0);
		if (sp->proc && !(sp->flags & MPR_SELECT_DISPOSED)) {
			if (sp->desiredMask != 0) {
				mprLog(8, log, 
					"%d: getFds: present %x, desired %x, disabled %d\n",
					sp->fd, sp->presentMask, sp->desiredMask, sp->disableMask);

				//
				//	Disable mask will be zero when we are alread servicing an
				//	event. 
				//
				mask = sp->desiredMask & sp->disableMask;
				if (mask & MPR_READABLE) {
					mprAssert(sp->presentMask == 0);
					FD_SET((unsigned) sp->fd, readInterest);
				} else {
					FD_CLR((unsigned) sp->fd, readInterest);
				}
				if (mask & MPR_WRITEABLE) {
					FD_SET((unsigned) sp->fd, writeInterest);
				} else {
					FD_CLR((unsigned) sp->fd, writeInterest);
				}
				if (mask & MPR_EXCEPTION) {
					FD_SET((unsigned) sp->fd, exceptInterest);
				} else {
					FD_CLR((unsigned) sp->fd, exceptInterest);
				}

			} else {
				FD_CLR((unsigned) sp->fd, readInterest);
				FD_CLR((unsigned) sp->fd, writeInterest);
				FD_CLR((unsigned) sp->fd, exceptInterest);
			}

			if (mask != 0 && sp->fd >= *maxFd) {
				*maxFd = sp->fd + 1;
			}
		}
		sp = (MprSelectHandler*) list.getNext(sp);
	}

	FD_SET(((unsigned) sock), readInterest);
	if (sock >= *maxFd) {
		*maxFd = sock + 1;
	}

	mprLog(8, log, "getFds: maxFd %d\n", *maxFd);
	unlock();
	return 1;
}

////////////////////////////////////////////////////////////////////////////////
#if UNUSED
void MprSelectService::checkList(char *file, int line)
{
	MprSelectHandler	*sp;
	int				count;

	lock();
	mprLog(1, "Checklist at %s, %d\n", file, line);
	sp = (MprSelectHandler*) list.getFirst();
	count = 0;
	while (sp) {
		mprAssert(sp->head == &list);
		mprAssert(sp->prev->next == sp);
		if (sp->next) {
			mprAssert(sp->next->prev == sp);
		}
		sp = (MprSelectHandler*) list.getNext(sp);
		count++;
	}
	mprAssert(count == list.getNumItems());
	unlock();
}
#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Service any I/O events. Cross platform select version. Called by the 
//	users app.
//

void MprSelectService::serviceIO(int readyFds, fd_set *readFds, 
	fd_set *writeFds, fd_set *exceptFds)
{
	MprSelectHandler	*sp, *next;
	char				buf[16];
	socklen_t			len;
	int					i, rc, mask, lastChange;

	mprLog(8, log, "serviceIO START\n");

#if WIN
	if (flags & MPR_ASYNC_SELECT) {
		mprAssert((flags & MPR_ASYNC_SELECT) == 0);
		return;
	}
#endif

	lock();
	//
	//	Clear out delayed close fds
	//
	for (i = 0; i < maxDelayedFd; i++) {
		closesocket(delayedFds[i]);
		FD_CLR((uint) delayedFds[i], readFds);
		mprLog(8, log, "serviceIO: delayed close for %d\n", delayedFds[i]);
	}
	maxDelayedFd = 0;

	//
	//	Service the select breakout socket first
	//
	if (FD_ISSET(sock, readFds)) {
		FD_CLR((uint) sock, readFds);
		len = sizeof(sa);
		rc = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*) &sa, &len);
		if (rc < 0) {
			closesocket(sock);
			sock = socket(AF_INET, SOCK_DGRAM, 0);
			rc = bind(sock, (struct sockaddr*) &sa, sizeof(sa)); 
			if (rc < 0 || sock < 0) {
				mprError(MPR_L, MPR_LOG, "Can't re-open select waker: %d\n");
			}
		}
		flags &= ~MPR_BREAK_REQUESTED;
		if (readyFds == 1) {
			mprLog(8, log, "serviceIO: solo breakout event\n");
			unlock();
			return;
		}
	}

	lastChange = listGeneration;

	//
	//	Now service all select handlers
	//
startAgain:
	sp = (MprSelectHandler*) list.getFirst();
	while (sp) {
		next = (MprSelectHandler*) list.getNext(sp);
		mask = 0;
		//
		//	Present mask is only cleared after the select handler callback has
		//	completed
		//
		mprLog(8, log, 
			"%d: ServiceIO: pres %x, desire %x, disable %d, set %d\n",
			sp->fd, sp->presentMask, sp->desiredMask, sp->disableMask, 
			FD_ISSET(sp->fd, readFds));

		mprAssert(sp->fd >= 0);
		if ((sp->desiredMask & MPR_READABLE) && FD_ISSET(sp->fd, readFds)) {
			mask |= MPR_READABLE;
			FD_CLR((uint) sp->fd, readFds);
			mprAssert(FD_ISSET(sp->fd, readFds) == 0);
		}
		if ((sp->desiredMask & MPR_WRITEABLE) && FD_ISSET(sp->fd, writeFds)) {
			mask |= MPR_WRITEABLE;
			FD_CLR((uint) sp->fd, writeFds);
		}
		if ((sp->desiredMask & MPR_EXCEPTION) && FD_ISSET(sp->fd, exceptFds)) {
			mask |= MPR_EXCEPTION;
			FD_CLR((uint) sp->fd, exceptFds);
		}
		if (mask == 0) {
			sp = next;
			continue;
		}

		mprAssert(!(sp->flags & MPR_SELECT_RUNNING));
		mprAssert(sp->presentMask == 0);
		mprAssert(sp->disableMask == -1);

		if (mask & sp->desiredMask) {
			sp->presentMask = mask;
			mprAssert(sp->inUse == 1);
			sp->flags |= MPR_SELECT_RUNNING;
#if BLD_FEATURE_MULTITHREAD
			if (mpr->poolService->getMaxPoolThreads() > 0) {
				//
				//	Will be re-enabled in selectProc() after the handler has run
				//
				sp->disableEvents(0);
				mprAssert(sp->presentMask != 0);

				mprLog(8, log, 
					"%d: serviceIO: creatingTask present %x, desired %x\n", 
					sp->fd, sp->presentMask, sp->desiredMask);
				MprTask *task;
				task = new MprTask(selectProcWrapper, (void*)sp, sp->priority);
				task->start();

			} else
#endif
			{
//	FUTURE -- can we get recursive events here with service thread. 
//	MAY NEED TO DISABLE EVENTS 
				mprLog(8, log, "%d: serviceIO: direct call\n", sp->fd);
				sp->presentMask = 0;
				sp->inUse++;

				unlock();
				(*sp->proc)(sp->handlerData, mask, 0);
				lock();

				sp->flags &= ~MPR_SELECT_RUNNING;
#if BLD_FEATURE_MULTITHREAD
				if (sp->stoppingCond) {
					sp->stoppingCond->signalCond();
				}
#endif
				if (--sp->inUse == 0 && sp->flags & MPR_SELECT_DISPOSED) {
					delete sp;
				}
			}
			if (lastChange != listGeneration) {
				//
				//	Note: sp or next may have been deleted while unlocked
				//	We have cleared the mask bits (FD_CLR) above so we 
				//	won't reprocess the event.
				//
				mprLog(9, log, "ServiceIO: rescan %d %d\n", lastChange, 
					listGeneration);
				goto startAgain;
			}
		}
		sp = next;
	}

#if BLD_FEATURE_MULTITHREAD
	if (flags & MPR_WAITING_FOR_SELECT) {
		flags &= ~MPR_WAITING_FOR_SELECT;
		cond->signalCond();
	}
#endif
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
#if WIN
//
//	Service any I/O events. Windows AsyncSelect version. Called by users app.
//

void MprSelectService::serviceIO(int sock, int winMask)
{
	MprSelectHandler	*sp;
	char 				buf[256];
	int					mask;

	if (!(flags & MPR_ASYNC_SELECT)) {
		mprAssert(flags & MPR_ASYNC_SELECT);
		return;
	}

	lock();
	mprLog(8, log, "serviceIO\n");

	if (winMask & FD_CLOSE) {
		// 
		//	Handle server initiated closes. See if the fd is in the delayed 
		//	close list. 
		//
		for (int i = 0; i < maxDelayedFd; i++) {
			if (delayedFds[i] == sock) {
				mprLog(8, log, "serviceIO: delayed close for %d\n", sock);
				while (recv(sock, buf, sizeof(buf), 0) > 0) {
					;
				}
				delayedFds[i] = -1;
				closesocket(sock);

				for (int j = maxDelayedFd - 1; j >= 0; j--) {
					if (delayedFds[j] >= 0) {
						break;
					}
				}
				maxDelayedFd = j + 1;
				unlock();
				return;
			}
		}
		mprLog(7, log, "serviceIO: Client initiated close for %d\n", sock);
	}

	sp = (MprSelectHandler*) list.getFirst();
	//
	//	FUTURE -- this is slow
	//
	while (sp) {
		if (sp->fd == sock) {
			break;
		}
		sp = (MprSelectHandler*) list.getNext(sp);
	}
	if (sp == 0) {
		//
		//	If the server forcibly closed the socket, we may still get a read
		//	event. Just ignore it.
		//
		mprLog(2, log, "%d: serviceIO: NO HANDLER, winEvent %x\n", 
			sock, winMask);
		unlock();
		return;
	}

	//
	//	disableMask will be zero if we are already servicing an event
	//
	mask = sp->desiredMask & sp->disableMask;
	mprAssert(!(sp->flags & MPR_SELECT_RUNNING));

	if (mask == 0) {
		//
		//	Already have an event scheduled so we must not schedule another yet
		//	We should have disabled events, but a message may already be in the
		//	message queue.
		//
		mprLog(2, log, 
			"%d: serviceIO: NULL event sp %x, winMask %x, desired %x, "
			"disable %x, flags %x\n", 
			sock, sp, winMask, sp->desiredMask, sp->disableMask, sp->flags);
		unlock();
		return;
	}

	mprLog(8, log, 
		"%d: serviceIO MASK winMask %x, desired %x, disable %x, flags %x\n", 
		sock, winMask, sp->desiredMask, sp->disableMask, sp->flags);

	//
	//	Mask values: READ==1, WRITE=2, ACCEPT=8, CONNECT=10, CLOSE=20
	//	Handle client initiated FD_CLOSE here.
	//

	if (winMask & FD_CLOSE) {
		sp->flags |= MPR_SELECT_CLIENT_CLOSED;
	}
	if (winMask & (FD_READ | FD_ACCEPT | FD_CLOSE)) {
		sp->presentMask |= MPR_READABLE;
	}
	if (winMask & (FD_WRITE | FD_CONNECT)) {
		sp->presentMask |= MPR_WRITEABLE;
	}

	if (sp->presentMask) {
		mprAssert(sp->inUse == 1);
		sp->flags |= MPR_SELECT_RUNNING;
#if BLD_FEATURE_MULTITHREAD
		if (mpr->poolService->getMaxPoolThreads() > 0) {
			MprTask *task;
			sp->disableEvents(0);
			mprAssert(sp->presentMask != 0);

			mprLog(8, log, 
				"%d: serviceIO: creatingTask present %x, desired %x\n", 
				sp->fd, sp->presentMask, sp->desiredMask);
			task = new MprTask(selectProcWrapper, (void*)sp, sp->priority);
			task->start();

		} else
#endif
		{
			mprLog(8, log, "%d: serviceIO: direct call\n", sp->fd);
			sp->presentMask = 0;
			sp->inUse++;
			if (mpr->isRunningEventsThread()) {
				sp->disableEvents(0);
			}

			mprLog(8, log, "serviceIO -- calling handler directly\n");
			unlock();
			(*sp->proc)(sp->handlerData, mask, 0);
			lock();

			sp->flags &= ~MPR_SELECT_RUNNING;
#if BLD_FEATURE_MULTITHREAD
			if (sp->stoppingCond) {
				sp->stoppingCond->signalCond();
			} else if (mpr->isRunningEventsThread()) {
				sp->enableEvents(0);
			}
#endif
			if (--sp->inUse == 0 && sp->flags & MPR_SELECT_DISPOSED) {
				delete sp;
			}
		}
	} else {
		mprLog(4, "serviceIO: Warning got event but no action %x\n", winMask);
	}
	unlock();
}

#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Break out of the select()/message dispatch(WIN) wait
//

void MprSelectService::awaken(int wait)
{
#if BLD_FEATURE_MULTITHREAD
	char	c;
	int		count;

	if (mpr->poolService->getMaxPoolThreads() == 0 && 
			!mpr->isRunningEventsThread()) {
		return;
	}

#if WIN
	if (flags & MPR_ASYNC_SELECT) {
		PostMessage((HWND) getHwnd(), WM_NULL, 0, 0L);
		return;
	}
#endif

	lock();
	mprLog(8, log, "awaken: wait %d\n", wait);
	if (sock >= 0 && !(flags & MPR_BREAK_REQUESTED)) {
		count = sendto(sock, &c, 1, 0, (struct sockaddr*) &sa, sizeof(sa));
		if (count == 1) {
			flags |= MPR_BREAK_REQUESTED;
		} else {
			mprLog(6, log, "Breakout send failed: %d\n", errno);
		}
	}
	if (wait) {
		//
		//	Potential bug here. If someone does a socketClose using 
		//	the primary thread that is also being used by select. That will
		//	call awaken(1) which will get here. If they are multithreaded,
		//	they will lock the select thread forever
		//
		flags |= MPR_WAITING_FOR_SELECT;
		unlock();
		cond->waitForCond(-1);
	} else {
		unlock();
	}
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Do a delayed close on a file/socket
//

void MprSelectService::delayedClose(int fd)
{
	lock();
	mprLog(7, log, "%d: requesting delayed close, maxDelayedFd %d\n", 
		fd, maxDelayedFd);

	if (maxDelayedFd < FD_SETSIZE) {
		delayedFds[maxDelayedFd++] = fd;

	} else {
		mprLog(7, log, "%d: but doing immediate close\n", fd);
		closesocket(fd);
	}
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Configure the breakout port
//

void MprSelectService::setPort(int n) 
{ 
	port = n; 
}

////////////////////////////////////////////////////////////////////////////////
#if WIN
//
//	Turn on/off async select mode
//

void MprSelectService::setAsyncSelectMode(bool asyncSelect) 
{ 
	lock();
	flags |= MPR_ASYNC_SELECT;
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return async select mode
//

bool MprSelectService::getAsyncSelectMode() 
{ 
	bool	rc;

	lock();
	rc = (flags & MPR_ASYNC_SELECT);
	unlock();
	return rc;
}

#endif
////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MprSelectHandler ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Create a handler. Priority is only observed when MULTITHREAD
//

MprSelectHandler::MprSelectHandler(int fd, int mask, MprSelectProc proc, 
	void *data, int priority)
{
	mprAssert(fd >= 0);

#if LINUX || MACOSX
	if (fd >= FD_SETSIZE) {
		mprError(MPR_L, MPR_LOG, 
			"File descriptor %d exceeds max select of %d\n", fd, FD_SETSIZE);
	}
#endif

	if (priority == 0) {
		priority = MPR_NORMAL_PRIORITY;
	}
	this->fd		= fd;
	this->priority	= priority;
	this->proc		= proc;

	flags			= 0;
	handlerData		= data;
	inUse			= 1;
	log				= mpr->selectService->getLog();
	presentMask		= 0;
	disableMask		= -1;
	selectService	= mpr->selectService;

#if BLD_FEATURE_MULTITHREAD
	stoppingCond	= 0;
#endif
	mprLog(8, log, "%d: MprSelectHandler: new handler\n", fd);

#if WIN
	if (selectService->getFlags() & MPR_ASYNC_SELECT) {
		desiredMask = 0;
		selectService->insertHandler(this);
		setInterest(mask);
	} else 
#endif
	{
		desiredMask = mask;
		selectService->insertHandler(this);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return TRUE if disposed completely.
//

bool MprSelectHandler::dispose()
{
	MprSelectService	*ss;

	mprLog(8, log, "%d: SelectHandler::dispose: inUse %d\n", fd, inUse);

	ss = selectService;
	ss->lock();

	mprAssert(inUse > 0);
	if (flags & MPR_SELECT_DISPOSED) {
		mprAssert(0);
		ss->unlock();
		return 0;
	}
	flags |= MPR_SELECT_DISPOSED;
	mprLog(8, log, "%d: dispose: inUse %d\n", fd, inUse);

	//
	//	Incase dispose is called from within a handler (ie. won't delete)
	//	we must remove from the select list immediately.
	//
	if (getList()) {
		selectService->removeHandler(this);
	}

	if (--inUse == 0) {
		delete this;
		ss->unlock();
		return 1;
	}
	ss->unlock();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Delete a select handler. We make sure there are no outstanding tasks 
//	scheduled before we complete the deleting.
//

MprSelectHandler::~MprSelectHandler()
{
	mprLog(8, log, "%d: MprSelectHandler Destructor\n", fd);

	if (flags & MPR_SELECT_CLOSEFD) {
		mprLog(8, log, "%d: ~MprSelectHandler close on dispose\n", fd);
		close(fd);
	}

	//
	//	Just in case stop() was not called
	//
	selectService->lock();
	if (getList()) {
		mprLog(3, "MprSelectHandler destructor -- still in list\n");
		selectService->removeHandler(this);
	}
	mprAssert(inUse == 0);
	selectService->unlock();
}

////////////////////////////////////////////////////////////////////////////////

int MprSelectHandler::stop(int timeout)
{
	MprSelectService	*ss;
	int					rc;

	mprLog(8, log, "%d: selectHandler::stop\n", fd);
	ss = selectService;
	ss->lock();

	if (getList()) {
		ss->removeHandler(this);
	}

#if BLD_FEATURE_MULTITHREAD
	//
	//	The timer is running -- just wait for it to complete. Increment inUse
	//	so it doen't get deleted from underneath us.
	//
	inUse++;
	while (timeout > 0 && (flags & MPR_SELECT_RUNNING)) {
		int start;
		if (stoppingCond == 0) {
			stoppingCond = new MprCond();
		}
		start = mprGetTime(0);
		ss->unlock();
		stoppingCond->waitForCond(timeout);
		ss->lock();
		timeout -= mprGetTime(0) - start;
	}

	if (stoppingCond) {
		delete stoppingCond;
		stoppingCond = 0;
	}
#endif
	rc = (flags & MPR_SELECT_RUNNING) ? -1 : 0;

	if (--inUse == 0 && flags & MPR_SELECT_DISPOSED) {
		delete this;
	}
	ss->unlock();
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_MULTITHREAD
//
//	Call select handler on a task thread from the pool
//

static void selectProcWrapper(void *data, MprTask *tp)
{
	MprSelectHandler	*sp;

	sp = (MprSelectHandler*) data;
	sp->selectProc(tp);
	tp->dispose();
}

////////////////////////////////////////////////////////////////////////////////

void MprSelectHandler::selectProc(MprTask *tp)
{
	MprSelectService	*ss;

	mprLog(8, log, "%d: selectProc BEGIN\n", fd);
	ss = selectService;

	ss->lock();
	inUse++;
	ss->unlock();

	(proc)(handlerData, presentMask, 1);
	mprLog(8, log, "%d: selectProc -- after proc\n", fd);

	ss->lock();
	mprLog(9, log, "%d: selectProc: inUse %d, flags %x\n", 
		fd, inUse, flags);
	flags &= ~MPR_SELECT_RUNNING;

#if BLD_FEATURE_MULTITHREAD
	if (stoppingCond) {
		stoppingCond->signalCond();
	}
#endif

	if (--inUse == 0 && flags & MPR_SELECT_DISPOSED) {
		mprLog(8, log, "%d: selectProc delete this\n", fd);
		delete this;
	} else {
		//
		//	EnableEvents can cause a new IO event which can invoke another
		//	pool thread. This call to makeIdle allows this thread to be
		//	selected to handle the new task rather than wakening another thread
		//
		tp->getThread()->makeIdle();
		if (! (flags & MPR_SELECT_DISPOSED)) {
			//
			//	FUTURE -- OPT. Only need to enable events if disableMask == 0
			//
			enableEvents(1);
		}
	}
	ss->unlock();
}

#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Modify a select handlers interested events
//

void MprSelectHandler::setInterest(int mask)
{
	selectService->lock();

	mprLog(8, log, "%d: setInterest: new mask %x, old %x, disableMask %d\n", 
		fd, mask, desiredMask, disableMask);

	if ((desiredMask & disableMask) == (mask & disableMask)) {
		desiredMask = mask;
	} else {
		desiredMask = mask;
#if WIN
		if (selectService->getFlags() & MPR_ASYNC_SELECT) {
			setWinInterest();
		}
#endif
		selectService->modifyHandler(this, 1);
	}
	selectService->unlock();
}

////////////////////////////////////////////////////////////////////////////////
#if WIN

void MprSelectHandler::setWinInterest()
{
	int	eligible, winMask;

	winMask = 0;
	eligible = desiredMask & disableMask;
	if (eligible & MPR_READABLE) {
		winMask |= FD_READ | FD_ACCEPT | FD_CLOSE;
	}
	if (eligible & MPR_WRITEABLE) {
		winMask |= FD_WRITE | FD_CONNECT;
	}
	mprLog(8, log, 
	"%d: setWinInterest: winMask %x, desiredMask %x, disableMask %d\n", 
		fd, winMask, desiredMask, disableMask);

	WSAAsyncSelect(fd, selectService->getHwnd(), selectService->getMessage(), 
		winMask);
}

#endif
////////////////////////////////////////////////////////////////////////////////

void MprSelectHandler::disableEvents(bool wakeUp)
{
	selectService->lock();
	disableMask = 0;
#if WIN
	if (selectService->getFlags() & MPR_ASYNC_SELECT) {
		setWinInterest();
	}
#endif
	selectService->modifyHandler(this, wakeUp);
	selectService->unlock();
}

////////////////////////////////////////////////////////////////////////////////

void MprSelectHandler::enableEvents(bool wakeUp)
{
	selectService->lock();
	disableMask = -1;
	presentMask = 0;
#if WIN
	if (selectService->getFlags() & MPR_ASYNC_SELECT) {
		setWinInterest();
	}
#endif
	selectService->modifyHandler(this, 1);
	selectService->unlock();
}

////////////////////////////////////////////////////////////////////////////////

void MprSelectHandler::setProc(MprSelectProc newProc, int mask)
{
	selectService->lock();
	proc = newProc;
	setInterest(mask);
	selectService->unlock();
}

////////////////////////////////////////////////////////////////////////////////

void MprSelectHandler::setCloseOnDispose()
{
	flags |= MPR_SELECT_CLOSEFD;
}

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
