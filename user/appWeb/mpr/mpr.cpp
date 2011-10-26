///
///	@file 	mpr.cpp
/// @brief 	Library and application initialization
///
///	The user instantiates the MR class in their application, typically in 
///	main(). Users can initialize the library by creating an instance of
///	the Mpr class, or they can start the Mpr services such as the thread-task,
///	timer and select modules. 
///
///	Usage (FUTURE -- code):
///		Mpr	*mpr = new Mpr("trace.log:2");	// Mandatory
///		mpr->configure("myProduct.xml");			// Optional
///		mpr->start();								// Optional
///		// Full MR usage enabled here 
///		delete mpr;									// Mandatory
///
///	This module is thread-safe.
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

/////////////////////////////////// Locals /////////////////////////////////////

Mpr				*mpr;							// Global default Mpr instance
static bool		debugMode;						// Debugging or not

static char	copyright[] = 
	"Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.";


#if UNUSED
char *errMessages[] = {
	"Success", 
	"General error", 
	"Aborted", 
	"Already exists", 
	"Bad args", 
	"Bad format", 
	"Bad handle", 
	"Bad state", 
	"Bad syntax", 
	"Bad type", 
	"Bad value", 
	"Busy", 
	"Can't access", 
	"Can't complete", 
	"Can't create", 
	"Can't initialize", 
	"Can't open", 
	"Can't read", 
	"Can't write", 
	"Already deleted", 
	"Network error", 
	"Not found", 
	"Not initialized", 
	"Not ready", 
	"Read only", 
	"Timeout", 
	"Too many", 
	"Won't fit", 
	"Would block", 
};

#if WIN
char *windowsErrList[] =
{
    /*  0              */  "No error",
    /*  1 EPERM        */  "Operation not permitted",
    /*  2 ENOENT       */  "No such file or directory",
    /*  3 ESRCH        */  "No such process",
    /*  4 EINTR        */  "Interrupted function call",
    /*  5 EIO          */  "I/O error",
    /*  6 ENXIO        */  "No such device or address",
    /*  7 E2BIG        */  "Arg list too long",
    /*  8 ENOEXEC      */  "Exec format error",
    /*  9 EBADF        */  "Bad file number",
    /* 10 ECHILD       */  "No child processes",
    /* 11 EAGAIN       */  "Try again",
    /* 12 ENOMEM       */  "Out of memory",
    /* 13 EACCES       */  "Permission denied",
    /* 14 EFAULT       */  "Bad address",
    /* 15 ENOTBLK      */  "Unknown error",
    /* 16 EBUSY        */  "Resource busy",
    /* 17 EEXIST       */  "File exists",
    /* 18 EXDEV        */  "Improper link",
    /* 19 ENODEV       */  "No such device",
    /* 20 ENOTDIR      */  "Not a directory",
    /* 21 EISDIR       */  "Is a directory",
    /* 22 EINVAL       */  "Invalid argument",
    /* 23 ENFILE       */  "Too many open files in system",
    /* 24 EMFILE       */  "Too many open files",
    /* 25 ENOTTY       */  "Inappropriate I/O control operation",
    /* 26 ETXTBSY      */  "Unknown error",
    /* 27 EFBIG        */  "File too large",
    /* 28 ENOSPC       */  "No space left on device",
    /* 29 ESPIPE       */  "Invalid seek",
    /* 30 EROFS        */  "Read-only file system",
    /* 31 EMLINK       */  "Too many links",
    /* 32 EPIPE        */  "Broken pipe",
    /* 33 EDOM         */  "Domain error",
    /* 34 ERANGE       */  "Result too large",
    /* 35 EUCLEAN      */  "Unknown error",
    /* 36 EDEADLK      */  "Resource deadlock would occur",
    /* 37 UNKNOWN      */  "Unknown error",
    /* 38 ENAMETOOLONG */  "Filename too long",
    /* 39 ENOLCK       */  "No locks available",
    /* 40 ENOSYS       */  "Function not implemented",
    /* 41 ENOTEMPTY    */  "Directory not empty",
    /* 42 EILSEQ       */  "Illegal byte sequence",
    /* 43 ENETDOWN     */  "Network is down",
    /* 44 ECONNRESET   */  "Connection reset",
    /* 45 ECONNREFUSED */  "Connection refused",
    /* 46 EADDRINUSE   */  "Address already in use"

};

int windowsNerr = 47;
#endif
#endif // UNUSED

///////////////////////////// Forward Declarations /////////////////////////////

#if BLD_FEATURE_MULTITHREAD
static void serviceEventsWrapper(void *data, MprThread *tp);
#endif

//////////////////////////////////// Code //////////////////////////////////////

///
///	Initialize the MPR library and the appliation control object for the MPR. 
///

Mpr::Mpr(char *name)
{
	//
	//	We expect only one MR class -- store a reference for global use
	//	Prior to return of this method, beware that mpr-> is not fully 
	//	constructed!!!
	//
	mprAssert(mpr == 0);						// Should be only one instance
	mpr = this;

	appName = 0;
	appTitle = 0;
	buildType = 0;
	cpu = 0;
	domainName = 0;
	eventsThread = 0;
	flags = 0;
	headless = 0;
	os = 0;
	runAsService = 0;
	version = 0;

#if WIN
	appInstance = 0;
	hwnd = 0;
#endif

	appName = mprStrdup(name);				// Initial defaults
	appTitle = mprStrdup(name);			
	buildNumber = atoi(BLD_NUMBER);
	buildType = mprStrdup(BLD_TYPE);
	os = mprStrdup(BLD_OS);
	version = mprStrdup(BLD_VERSION);
	copyright[0] = copyright[0];			// Suppress compiler warning
	hostName = mprStrdup("localhost");
	serverName = mprStrdup("localhost");
	installDir = mprStrdup(".");

#if MPR_CPU == MPR_CPU_IX86
	cpu = mprStrdup("ix86");
#endif
#if MPR_CPU == MPR_CPU_SPARC
	cpu = mprStrdup("sparc");
#endif
#if MPR_CPU == MPR_CPU_PPC
	cpu = mprStrdup("ppc");
#endif
#if MPR_CPU == MPR_CPU_XSCALE
	cpu = mprStrdup("xscale");
#endif
#if MPR_CPU == MPR_CPU_ARM
	cpu = mprStrdup("arm");
#endif
	if (cpu == 0) {
		cpu = mprStrdup("unknown");
	}

#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
	timeMutex = new MprMutex();
	eventsMutex = new MprMutex();
#endif

#if BLD_FEATURE_LOG
//	logger = 0;
	logService = new MprLogService();
	defaultLog = new MprLogModule("default");
#endif
	platformInitialize();
	configSettings = new MprHashTable();

#if BLD_FEATURE_MULTITHREAD
	threadService = new MprThreadService();
#endif
#if BLD_FEATURE_CGI_MODULE
	cmdService = new MprCmdService();
#endif

	timerService = new MprTimerService();
	poolService = new MprPoolService("default");
	selectService = new MprSelectService();
	socketService = new MprSocketService();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Windup the MR
//

Mpr::~Mpr()
{
	mprLog(MPR_CONFIG, 0, "MPR Exiting\n");

	if (flags & MPR_STARTED && !(flags & MPR_STOPPED)) {
		stop(1);
	}

	delete socketService;
	delete selectService;
	delete poolService;
#if BLD_FEATURE_CGI_MODULE
	delete cmdService;
#endif
	delete timerService;

	//
	//	Log needs to know when the threadService has been deleted
	//
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
	delete timeMutex;
	delete eventsMutex;
#endif
	delete configSettings;

	mprFree(appName);
	mprFree(appTitle);
	mprFree(buildType);
	mprFree(cpu);
	mprFree(domainName);
	mprFree(hostName);
	mprFree(installDir);
	mprFree(os);
	mprFree(serverName);
	mprFree(version);

	mprLog(MPR_CONFIG, 0, "--------- MPR Shutdown ----------\n");

#if BLD_DEBUG
	mprMemStop();
#endif

#if BLD_FEATURE_MULTITHREAD
	delete threadService;
	threadService = 0;
#endif

#if BLD_FEATURE_LOG
	delete defaultLog;
	logService->stop();
//	if (logger) {
//		delete logger;
//	}
	delete logService;
#endif

	platformTerminate();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start the run-time services: timer, thread-task, select
//

int Mpr::start(int startFlags)
{
	int		rc = 0;

#if BLD_FEATURE_LOG
	logService->start();
#endif

	//
	//	Note: users can create timers before the timerService is started.
	//	They won't run until we hit the main event loop in any case which 
	//	processes timer and select events
	// 
	rc += platformStart(startFlags);
#if BLD_FEATURE_MULTITHREAD
	rc += threadService->start();
#endif
	rc += poolService->start();
	rc += selectService->start();
	rc += timerService->start();
	rc += socketService->start();
#if BLD_FEATURE_CGI_MODULE
	rc += cmdService->start();
#endif

	if (rc != 0) {
		mprError(MPR_L, MPR_USER, "Can't start MPR services");
		return MPR_ERR_CANT_INITIALIZE;
	}

#if BLD_FEATURE_MULTITHREAD
	if (startFlags & MPR_SERVICE_THREAD) {
		startEventsThread();
	}
#endif

	flags |= MPR_STARTED & (startFlags & MPR_USER_START_FLAGS);
	mprLog(3, "MPR services are ready\n");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Stop the MR service
//

int Mpr::stop(bool immediateStop)
{
	//
	//	Graceful termination
	//
	this->terminate(1);

#if BLD_FEATURE_LOG
	logService->shuttingDown();
#endif

	//
	//	All stop methods are idempotent
	//
	poolService->stop((immediateStop) ? 0 : MPR_TIMEOUT_STOP_TASK);
#if BLD_FEATURE_CGI_MODULE
	cmdService->stop();
#endif
	socketService->stop();
	selectService->stop();
#if BLD_FEATURE_MULTITHREAD
	threadService->stop((immediateStop) ? 0 : MPR_TIMEOUT_STOP_THREAD);
#endif
	timerService->stop();

	//
	//	Don't stop the log service as we want logging & trace to the bitter end
	//		logService->stop();
	//
	platformStop();
	flags |= MPR_STOPPED;

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_MULTITHREAD
//
//	Thread to service timer and socket events. Used only if the user does not
//	have their own main event loop.
//

void Mpr::startEventsThread()
{
	MprThread	*tp;

	mprLog(MPR_CONFIG, "Starting service thread\n");
	tp = new MprThread(serviceEventsWrapper, MPR_NORMAL_PRIORITY, 0, "s.0");
	tp->start();
	eventsThread = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Thread main for serviceEvents
//

static void serviceEventsWrapper(void *data, MprThread *tp)
{
	mpr->serviceEvents(0, -1);
}

#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Service timer and select/socket events on a service thread. Only used if
//	multi-threaded and the users does not define their own event loop.
//

void Mpr::serviceEvents(bool loopOnce, int maxTimeout)
{
	struct timeval	timeout;
	fd_set			readFds, writeFds, exceptFds;
	fd_set			readInterest, writeInterest, exceptInterest;
#if WIN
	fd_set			*readp, *writep, *exceptp;
#endif
	int				maxFd, till, lastGet, readyFds;

#if BLD_FEATURE_MULTITHREAD
	eventsMutex->lock();
	mprGetCurrentThread()->setPriority(MPR_SELECT_PRIORITY);
	//
	//	Set here also incase a user calls serviceEvents manually
	//
	eventsThread = 1;
#endif

	lastGet = -1;
	maxFd = 0;
	FD_ZERO(&readInterest);
	FD_ZERO(&writeInterest);
	FD_ZERO(&exceptInterest);

	do {

		if (runTimers() > 0) {
			till = 0;
		} else {
			till = getIdleTime();
		}

		//
		//	This will run tasks if poolThreads == 0 (single threaded). If 
		//	multithreaded, the thread pool will run tasks
		//
		if (runTasks() > 0) {				// Returns > 0 if more work to do
			till = 0;						// So don't block in select
		}

		//
		//	Mpr will populate with the FDs in use by MR on if necessary
		//
		if (getFds(&readInterest, &writeInterest, &exceptInterest, 
				&maxFd, &lastGet)) {
			//
			//	Masks have been rebuilt, so add user fds here ....
			//
		}

		//
		//	Copy as select will modify readFds etc.
		//
		memcpy((void*) &readFds, (void*) &readInterest, sizeof(readFds));
		memcpy((void*) &writeFds, (void*) &writeInterest, sizeof(readFds));
		memcpy((void*) &exceptFds, (void*) &exceptInterest, sizeof(exceptFds));

		if (maxTimeout > 0) {
			till = min(till, maxTimeout);
		}
		timeout.tv_sec = till / 1000;
		timeout.tv_usec = (till % 1000) * 1000;

#if WIN
		//
		//	Windows does not accept empty descriptor arrays
		//
		readp = (readFds.fd_count == 0) ? 0 : &readFds;
		writep = (writeFds.fd_count == 0) ? 0 : &writeFds;
		exceptp = (exceptFds.fd_count == 0) ? 0 : &exceptFds;
		readyFds = select(maxFd, readp, writep, exceptp, &timeout);
#else
		mprLog(7, "eventsThread: calling select: till %d\n", till);
		readyFds = select(maxFd, &readFds, &writeFds, &exceptFds, &timeout);
		mprLog(7, "eventsThread: select returns with %d events\n", readyFds);
#endif
		if (readyFds < 0) {
			if (mprGetOsError() != EINTR) {
				mprLog(0, "WARNING: select failed, errno %d\n", errno);
			}
		} else if (readyFds > 0) {
			serviceIO(readyFds, &readFds, &writeFds, &exceptFds);
		}
	} while (!isExiting() && !loopOnce);

#if BLD_FEATURE_MULTITHREAD
	eventsThread = 0;
	eventsMutex->unlock();
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience function
//

int Mpr::runTimers()
{ 
	return timerService->runTimers(); 
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience function
//

int Mpr::runTasks()
{ 
	return poolService->runTasks();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience function
//

int Mpr::getIdleTime()
{ 
	return timerService->getIdleTime();
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_MULTITHREAD

MprThread *Mpr::getCurrentThread()
{
	return threadService->getCurrentThread(); 
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience function
//

void Mpr::setPriority(int pri)
{
	threadService->getCurrentThread()->setPriority(pri);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience functions
//

MprThread *mprGetCurrentThread()
{
	return mpr->threadService->getCurrentThread();
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setMinPoolThreads(int n)
{
	poolService->setMinPoolThreads(n);
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setMaxPoolThreads(int n)
{
	poolService->setMaxPoolThreads(n);
}

////////////////////////////////////////////////////////////////////////////////

int Mpr::getMinPoolThreads()
{
	return poolService->getMinPoolThreads();
}

////////////////////////////////////////////////////////////////////////////////

int Mpr::getMaxPoolThreads()
{
	return poolService->getMaxPoolThreads();
}

////////////////////////////////////////////////////////////////////////////////

int mprGetMaxPoolThreads()
{
	return mpr->poolService->getMaxPoolThreads();
}

#endif // BLD_FEATURE_MULTITHREAD
////////////////////////////////////////////////////////////////////////////////
//
//	Exit the mpr gracefully. Instruct the event loop to exit.
//

void Mpr::terminate(bool graceful)
{
	if (! graceful) {
		exit(2);
	}
	lock();
	flags |= MPR_EXITING;
	unlock();
	selectService->awaken();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return true if Mpr is exiting
//

bool Mpr::isExiting()
{
	return flags & MPR_EXITING;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience function
//

int Mpr::getFds(fd_set *readInterest, fd_set *writeInterest, 
	fd_set *exceptInterest, int *maxFd, int *lastGet)
{
	return mpr->selectService->getFds(readInterest, writeInterest, 
		exceptInterest, maxFd, lastGet);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Convenience function
//

void Mpr::serviceIO(int readyFds, fd_set *readFds, fd_set *writeFds, 
	fd_set *exceptFds)
{
	mpr->selectService->serviceIO(readyFds, readFds, writeFds, exceptFds);
}

////////////////////////////////////////////////////////////////////////////////
#if WIN
//
//	Convenience function
//

void Mpr::serviceIO(int sock, int winMask)
{
	mpr->selectService->serviceIO(sock, winMask);
}

#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Set the applications name (one word by convention). Used mostly in creating
//	pathnames for application components.
//

void Mpr::setAppName(char *s)
{
	lock();
	if (appName) {
		mprFree(appName);
	}
	appName = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

char *Mpr::getAppName()
{
	return appName;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set the description of the application. Short, but can be multiword.
//	Used whereever we need to visibly refer to the application
//
void Mpr::setAppTitle(char *s)
{
	lock();
	if (appTitle) {
		mprFree(appTitle);
	}
	appTitle = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

char *Mpr::getAppTitle()
{
	return appTitle;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setBuildType(char *s)
{
	lock();
	if (buildType) {
		mprFree(buildType);
	}
	buildType = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

char *Mpr::getBuildType()
{
	/* FUTURE -- not thread safe */
	return buildType;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setBuildNumber(int num)
{
	/* FUTURE -- waste of time locking here if we don't lock in the get code */
	mprAssert(0 <= num && num < 99999);
	lock();
	buildNumber = num;
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

int Mpr::getBuildNumber()
{
	return buildNumber;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setOs(char *s)
{
	lock();
	if (os) {
		mprFree(os);
	}
	os = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

char *Mpr::getOs()
{
	return os;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setCpu(char *s)
{
	lock();
	if (cpu) {
		mprFree(cpu);
	}
	cpu = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

char *Mpr::getCpu()
{
	return cpu;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Version strings are: maj.min.patch.build. E.g. 2.0.1.4
//

void Mpr::setVersion(char *s)
{
	lock();
	if (version) {
		mprFree(version);
	}
	version = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////

char *Mpr::getVersion()
{
	return version;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_LOG

int Mpr::setLogSpec(char *file)
{
	if (logService == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}
	return logService->setLogSpec(file);
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::addListener(MprLogListener *lp)
{
	mprAssert(logService);

	logService->addListener(lp);
}

#endif // BLD_FEATURE_LOG
////////////////////////////////////////////////////////////////////////////////

void Mpr::setInstallDir(char *dir)
{
	lock();
	if (installDir) {
		mprFree(installDir);
	}
	installDir = mprStrdup(dir);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the applications installation directory
//

char *Mpr::getInstallDir()
{
	return installDir;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Full host name with domain. E.g. "server.domain.com"
//

void Mpr::setHostName(char *s)
{
	lock();
	if (hostName) {
		mprFree(hostName);
	}
	hostName = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the fully qualified host name
//

char *Mpr::getHostName()
{
	return hostName;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Server name portion (no domain name)
//

void Mpr::setServerName(char *s)
{
	lock();
	if (serverName) {
		mprFree(serverName);
	}
	serverName = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the server name
//

char *Mpr::getServerName()
{
	return serverName;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Set the domain name 
//

void Mpr::setDomainName(char *s)
{
	lock();
	if (domainName) {
		mprFree(domainName);
	}
	domainName = mprStrdup(s);
	unlock();
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the domain name
//

char *Mpr::getDomainName()
{
	return domainName;
}

////////////////////////////////////////////////////////////////////////////////
#if WIN

bool Mpr::getAsyncSelectMode() 
{ 
	return selectService->getAsyncSelectMode();
}

////////////////////////////////////////////////////////////////////////////////

long Mpr::getInst()
{
	return (long) appInstance;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setInst(long inst)
{
	appInstance = inst;
}

#endif
////////////////////////////////////////////////////////////////////////////////

bool Mpr::isService()
{
	return runAsService;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setService(bool service)
{
	runAsService = service;
}

////////////////////////////////////////////////////////////////////////////////
#if WIN

HWND Mpr::getHwnd()
{
	return hwnd;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setHwnd(HWND h)
{
	hwnd = h;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setSocketHwnd(HWND h) 
{
	selectService->setHwnd(h);
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setSocketMessage(int m) 
{ 
	selectService->setMessage(m);
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setAsyncSelectMode(bool on) 
{ 
	selectService->setAsyncSelectMode(on);
}

#endif

////////////////////////////////////////////////////////////////////////////////

int Mpr::getHeadless()
{
	return headless;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::setHeadless(int flag)
{
	headless = flag;
}

////////////////////////////////////////////////////////////////////////////////

Mpr *mprGetMpr()
{
	return mpr;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get a configuration string value
//

char *Mpr::getConfigStr(char *key, char *defaultValue)
{
#if BLD_FEATURE_XML_CONFIG
	char	*value;

	if (readXmlStr(configSettings, key, &value) < 0) {
		return defaultValue;
	}
	return value;
#else
	return defaultValue;
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get a configuration integer value
//

int Mpr::getConfigInt(char *key, int defaultValue)
{	
#if BLD_FEATURE_XML_CONFIG
	int		value;

	if (readXmlInt(configSettings, key, &value) < 0) {
		return defaultValue;
	}
	return value;
#else
	return defaultValue;
#endif
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_XML_CONFIG
//
//	Configure the MR library by opening the product.xml file.
//

int Mpr::configure(char *configFile)
{
	char	*logSpec;

	//
	//	Open the product.xml file
	//
	if (configFile == 0 || *configFile == '\0') {
		return MPR_ERR_BAD_ARGS;
	}

	if (openXmlFile(configFile) < 0) {
		mprError(MPR_L, MPR_USER, 
			"Can't open product configuration file: %s", configFile);
		return MPR_ERR_CANT_OPEN;
	}

	//
	//	Extract the standard settings
	//
	setAppTitle(getConfigStr("appTitle", "mprAppTitle"));
	setAppName(getConfigStr("appName", "mprAppName"));
	setHeadless(getConfigInt("headless", headless));

	//
	//	Redirect error log output if required
	//
	logSpec = getConfigStr("logSpec", 0);
	if (logSpec && *logSpec) {
		if (logService->isLogging()) {
			mprError(MPR_L, MPR_LOG, 
				"Logging already enabled. Ignoring logSpec directive in %s", 
				configFile);
		} else {
			logService->stop();
			logService->setLogSpec(logSpec);
			logService->start();
		}
	}

#if BLD_FEATURE_MULTITHREAD
	//
	//	Define the thread task limits
	//
	poolService->setMaxPoolThreads(getConfigInt("maxMprPoolThreads", 0));
	poolService->setMinPoolThreads(getConfigInt("minMprPoolThreads", 0));
#endif

	//
	//	Select breakout port
	//
	selectService->setPort(getConfigInt("selectPort", -1));
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Basic XML parser to extract name / value parirs and store in a symbol table.
//

int Mpr::openXmlFile(char *path)
{
	struct stat	sbuf;
	char		*buf, *name, *cp, *value;
	int			fd, keywordCount, len;

	mprAssert(path && *path);

	//
	//	Read the XML file entirely into memory
	//
	if ((fd = open(path, O_RDONLY)) < 0) {
		mprError(MPR_L, MPR_USER, "Can't open file: %s", path);
		return -1;
	}

	stat(path, &sbuf);
	buf = new char[sbuf.st_size + 1];

	if ((len = read(fd, buf, sbuf.st_size)) < 0) {
		mprError(MPR_L, MPR_USER, "Can't read file: %s", path);
		delete[] buf;
		return -1;
	}
	buf[len] = '\0';
	close(fd);

	//
	//	Read all key values into a symbol table. This is hard-coded parsing. 
	//	We expect a two-level XML tree with all name tags directly under 
	//	the root tag.
	//
	keywordCount = 0;
	cp = strstr(buf, "<config ");
	while (cp && *cp) {
		cp++;
		if ((name = strchr(cp, '<')) == NULL) {
			break;
		}
		name++;
		if (name[0] == '!' && name[1] == '-' && name[2] == '-') {
			cp = name;
			continue;
		}
		if ((value = strchr(name, '>')) == NULL) {
			break;
		}
		*value++ = '\0';
		if ((cp = strchr(value, '<')) == NULL) {
			break;
		}
		*cp++ = '\0';
		if ((cp = strchr(cp, '>')) == NULL) {
			break;
		}
		configSettings->insert(new StringHashEntry(name, value));
		keywordCount++;
	}

	//
	//	Sanity check on the parsing. We should have found at least 4 keywords
	//
	if (keywordCount < 4) {
		mprError(MPR_L, MPR_USER, "Can't parse file: %s", path);
	}
	
	delete[] buf;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Read a string configuration item. MprUniType is set to NULL on an error
//

int Mpr::readXmlStr(MprHashTable *symTab, char *key, char **value)
{
	StringHashEntry		*ep;

	mprAssert(key);
	mprAssert(value);

	if ((ep = (StringHashEntry*) symTab->lookup(key)) == 0) {
		*value = 0;
		return MPR_ERR_NOT_FOUND;
	}
	*value = ep->getValue();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Read an integer configuration item. MprUniType is set to -1 on an error.
//

int Mpr::readXmlInt(MprHashTable *symTab, char *key, int *value)
{
	StringHashEntry		*ep;

	mprAssert(key);
	mprAssert(value);

	//
	//	FUTURE -- could create IntHashEntry or use Unitype
	//
	if ((ep = (StringHashEntry*) symTab->lookup(key)) == 0) {
		*value = -1;
		return MPR_ERR_NOT_FOUND;
	}
	*value = atoi(ep->getValue());
	return 0;
}

#endif // BLD_FEATURE_XML_CONFIG
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MprScriptService ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprScriptService::MprScriptService(const char *name)
{
	this->name = mprStrdup(name);
	mpr->scriptServices.insert(this);
}

////////////////////////////////////////////////////////////////////////////////

MprScriptService::~MprScriptService()
{
	mpr->scriptServices.remove(this);
	mprFree(name);
}

////////////////////////////////////////////////////////////////////////////////

MprScriptEngine* MprScriptService::newEngine(void *data, MprHashTable *vars, 
	MprHashTable *functions)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	NOTE: method in Mpr class to locate a given scripting service by name
//

MprScriptService *Mpr::lookupScriptService(char *name)
{
	MprScriptService	*ss;

	ss = (MprScriptService*) mpr->scriptServices.getFirst();
	while (ss) {
		if (strcmp(ss->getName(), name) == 0) {
			return ss;
		}
		ss = (MprScriptService*) mpr->scriptServices.getNext(ss);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprScriptEngine //////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprScriptEngine::MprScriptEngine()
{
}

////////////////////////////////////////////////////////////////////////////////

MprScriptEngine::~MprScriptEngine()
{
}

////////////////////////////////////////////////////////////////////////////////

char *MprScriptEngine::evalScript(char *script, char **errMsg)
{
	return "0";
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// C API ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
extern "C" {

bool mprGetDebugMode()
{
	return debugMode;
}

////////////////////////////////////////////////////////////////////////////////

void mprSetDebugMode(bool on)
{
	debugMode = on;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Map the O/S error code to portable error codes.
//

int mprGetOsError()
{
#if WIN
	int		rc;
	rc = GetLastError();
	if (rc == 232) {
		return EAGAIN;
	}
	return rc;
#else
	return errno;
#endif
}

////////////////////////////////////////////////////////////////////////////////
#if UNUSED

char *mprGetErrorMsg(int err)
{
	//
	//	MPR_ERR_BASE is -200
	//
	if (err < MPR_ERR_BASE) {
		err = MPR_ERR_BASE - err;
		if (err < 0 || err >= (MPR_ERR_BASE - MPR_ERR_MAX)) {
			return "Bad error code";
		}
		return errMessages[err];
	} else {
		//
		//	Negative O/S error code. Map to a positive standard Posix error.
		//
		err = -err;
#if LINUX || MACOSX
		if (err < 0) {
			return "Bad O/S error code";
		}
		//
		//	FUTURE: we currently only use this inside thread locks, but 
		//	this should be cleaned up.
		//
		static char buf[80];
		return strerror_r(err, buf, sizeof(buf) - 1);
		// return (char*) buf;
#endif
#if SOLARIS
		if (err < 0) {
			return (char*) "Bad O/S error code";
		}
		//
		//	FUTURE: we currently only use this inside thread locks, but 
		//	this should be cleaned up.
		//
		return strerror(err);
#endif
#if WIN
		if (err < 0 || err >= windowsNerr) {
			return "Bad O/S error code";
		}
		return (char*) windowsErrList[err];
#endif
	}
}

#endif
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_MULTITHREAD

char *mprGetCurrentThreadName()
{
	return mpr->threadService->getCurrentThread()->getName();
}

#endif
////////////////////////////////////////////////////////////////////////////////
} // extern "C"

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
