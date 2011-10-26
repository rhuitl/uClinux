///
///	@file 	appWeb.cpp
/// @brief 	AppWeb main program for Unix and for a Windows console application
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

#include	"appWeb/appWeb.h"

//////////////////////////////////// Locals ////////////////////////////////////

static Mpr		*mp;
static MaServer	*server;

char *okEnv[] =
{
    // variable name starts with 
    "HTTP_",
    "SSL_",

    // variable name is 
    "AUTH_TYPE=",
    "CONTENT_LENGTH=",
    "CONTENT_TYPE=",
    "DATE_GMT=",
    "DATE_LOCAL=",
    "DOCUMENT_NAME=",
    "DOCUMENT_PATH_INFO=",
    "DOCUMENT_ROOT=",
    "DOCUMENT_URI=",
    "FILEPATH_INFO=",
    "GATEWAY_INTERFACE=",
    "HTTPS=",
    "LAST_MODIFIED=",
    "PATH_INFO=",
    "PATH_TRANSLATED=",
    "QUERY_STRING=",
    "QUERY_STRING_UNESCAPED=",
    "REMOTE_ADDR=",
    "REMOTE_HOST=",
    "REMOTE_IDENT=",
    "REMOTE_PORT=",
    "REMOTE_USER=",
    "REDIRECT_QUERY_STRING=",
    "REDIRECT_STATUS=",
    "REDIRECT_URL=",
    "REQUEST_METHOD=",
    "REQUEST_URI=",
    "SCRIPT_FILENAME=",
    "SCRIPT_NAME=",
    "SCRIPT_URI=",
    "SCRIPT_URL=",
    "SERVER_ADMIN=",
    "SERVER_NAME=",
    "SERVER_ADDR=",
    "SERVER_PORT=",
    "SERVER_PROTOCOL=",
    "SERVER_SOFTWARE=",
    "UNIQUE_ID=",
    "USER_NAME=",
    "TZ=",
    NULL
};

static char 		*serverRoot;
#if BLD_FEATURE_LOG
static MprLogToFile	*logger;
#endif

////////////////////////////// Forward Declarations ////////////////////////////

#if !WIN
static void catchSignal(int signo, siginfo_t *info, void *arg);
static void initSignals();
#endif
static void memoryFailure(int askSize, int totalHeapMem, int limit);
static void printVersion();
static void printUsage(char *programName);
static int	securityChecks(char *program);

#if UNUSED
static int	getBrowserPath(char **path, int max);
static void runBrowser(char *page);
static int	startBrowser();
#endif

#if !BLD_FEATURE_ROMFS
static int	copyTemplate(char *path, char *serverRoot, char *confFile);
static int	copyFile(char *from, char *to);
#endif

//////////////////////////////////// Code //////////////////////////////////////
//
//	Normal main
//

int main(int argc, char *argv[])
{
	MaHttp		*http;
	char		*programName, *argp, *logSpec, *confFile, *path;
	int			c, errflg, kill, timeStamps, poolThreads;
	bool		outputConfig;
	int			daemonize, outputVersion;
	MprCmdLine 	cmdLine(argc, argv, "cdDf:kl:mp:r:TV");

	mprSetMemHandler(memoryFailure);
	mprCreateMemHeap(0, 64 * 1024, MAXINT);

	programName = mprGetBaseName(argv[0]);
	poolThreads = -1;
	daemonize = timeStamps = kill = errflg = 0;
	logSpec = 0;
	confFile = "appWeb.conf";
	outputVersion = 0;
	outputConfig = 0;

#if BLD_FEATURE_LOG
	logger = 0;
#endif
#if WIN
	char	programBuf[MPR_MAX_FNAME], dir[MPR_MAX_FNAME];
	GetModuleFileName(0, programBuf, sizeof(programBuf) - 1);
	mprGetDirName(dir, sizeof(dir), programBuf);
	for (char *s = dir; *s; s++) {
		if (*s == '\\') {
			*s = '/';
		}
	}
	serverRoot = mprStrdup(dir);
#else
	serverRoot = mprStrdup(BLD_PREFIX);
#endif

	while ((c = cmdLine.next(&argp)) != EOF) {
		switch(c) {
		case 'c':
			outputConfig = 1;
			logSpec = "stdout:0";
			break;

		case 'd':
			daemonize++;
			break;

		case 'D':
			mprSetDebugMode(1);
			break;

		case 'f':
			confFile = argp;
			break;

		case 'k':
			kill++;
			logSpec = 0;
			break;

		case 'l':
			logSpec = argp;
			break;

		case 'm':
			mprRequestMemStats(1);
			break;

		case 'p':
			poolThreads = atoi(argp);
			break;

		case 'r':
			mprFree(serverRoot);
			serverRoot = mprStrdup(argp);
			break;

		case 'T':
			timeStamps++;
			break;

		case 'V':
			outputVersion++;
			break;
			
		default:
			errflg++;
			break;
		}
	}
	if (errflg) {
		printUsage(argv[0]);
		exit(2);
	}	

	mp = new Mpr(programName);
	mp->setAppTitle("Mbedthis AppWeb");
	mp->setAppName("MbedthisAppWeb");
	mp->setHeadless(1);
#if !WIN
	initSignals();
#endif

	if (kill) {
		mp->killMpr();
		delete mp;
		exit(0);
	}

	if (outputVersion) {
		printVersion();
		delete mp;
		exit(0);
	}

#if BLD_FEATURE_LOG
	logger = new MprLogToFile();
	mp->addListener(logger);
	if (timeStamps) {
		logger->enableTimeStamps(1);
	}

#if !BLD_FEATURE_ROMFS
	if (logSpec) {
		mp->setLogSpec(logSpec);
	}
#else
	//
	//	If ROMming, we can only log to stdout as we can't log to a read-only
	//	file system!! Alternatively, you can design your own listener and 
	//	install it here.
	//
	if (logSpec) {
		if (strncmp(logSpec, "stdout", 6) == 0) {
			mp->setLogSpec(logSpec);
		} else {
			mprFprintf(MPR_STDERR, "Can't log to %s when using ROMFS\n", 
				logSpec);
		}
	}
#endif
#endif

	if (securityChecks(argv[0]) < 0) {
		exit(3);
	}

	//
	//	Start the MPR services
	//
	if (mp->start(MPR_KILLABLE) < 0) {
		mprError(MPR_L, MPR_USER, "Can't start MPR for %s", mp->getAppTitle());
		exit(4);
	}

	//
	//	Create the top level http service and default HTTP server
	//
	http = new MaHttp();
	server = new MaServer(http, "default", serverRoot);

	//
	//	Load the statically linked modules
	//
	maLoadStaticModules();

#if BLD_FEATURE_ROMFS
	//
	//	Change the name from defaultRomFiles to whatever romName you give to
	//	httpComp when compiling your rom pages
	//
	extern MaRomInode	defaultRomFiles[];
	MaRomFileSystem *romFileSystem = 
		new MaRomFileSystem(defaultRomFiles);
	server->setFileSystem(romFileSystem);
#endif

	mprAllocSprintf(&path, MPR_MAX_FNAME, "%s/%s", serverRoot, confFile);
#if !BLD_FEATURE_ROMFS
	if (access(path, R_OK) < 0) {
		if (copyTemplate(path, serverRoot, confFile) < 0) {
			mprError(MPR_L, MPR_USER, "Can't access config file %s", path);
			exit(5);
		}
	}
#endif

	//
	//	Configure, then start the http service and hosts specified in 
	//	appWeb.conf
	//
	if (server->configure(path, outputConfig) < 0) {
		mprError(MPR_L, MPR_USER, "Can't configure server using %s", path);
		exit(6);
	}
	mprFree(path);

#if BLD_FEATURE_MULTITHREAD
	MaLimits *limits = http->getLimits();
	if (poolThreads >= 0) {
		limits->maxThreads = poolThreads;
		if (limits->minThreads > limits->maxThreads) {
			limits->minThreads = limits->maxThreads;
		}
	}
	if (limits->maxThreads > 0) {
		mp->setMaxPoolThreads(limits->maxThreads);
		mp->setMinPoolThreads(limits->minThreads);
	}
#endif

	if (! outputConfig) {
		if (http->start() < 0) {
			mprError(MPR_L, MPR_USER, "Can't start server, exiting.");
			exit(7); 

		} else {
#if LINUX && BLD_FEATURE_RUN_AS_SERVICE
			if (daemonize && mp->makeDaemon(1) < 0) {
				mprError(MPR_L, MPR_USER, "Could not run in the background");
			}
#endif
#if BLD_FEATURE_MULTITHREAD
			mprLog(MPR_CONFIG, "HTTP services are ready with %d pool threads\n",
				limits->maxThreads);
#else
			mprLog(MPR_CONFIG, "HTTP services are ready (single-threaded)\n");
#endif
			mp->serviceEvents(0, -1);
			http->stop();
		}
	}

	mp->stop(0);
	delete server;
	delete http;
	mprFree(serverRoot);

#if BLD_FEATURE_ROMFS
	delete romFileSystem;
#endif

	delete mp;
#if BLD_FEATURE_LOG
	if (logger) {
		delete logger;
	}
#endif

	mprMemClose();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if !BLD_FEATURE_ROMFS

static int copyTemplate(char *path, char *serverRoot, char *confFile)
{ 
	char	standard[MPR_MAX_FNAME];

	//
	//	Initial install comes with new.conf which will be copied to 
	//	appWeb.conf if it does not already exist
	//
	mprSprintf(standard, MPR_MAX_FNAME, "%s/new.conf", serverRoot);
	if (access(standard, R_OK) < 0) {
		return MPR_ERR_CANT_OPEN;
	}
	if (copyFile(standard, path) < 0) {
		mprError(MPR_L, MPR_USER, "Can't copy %s to %s", standard, path);
		return MPR_ERR_CANT_WRITE;
	}
	unlink(standard);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if UNUSED
//
//	Start the browser at install time if required
//

static int startBrowser()
{
	char	path[MPR_MAX_FNAME];

	mprSprintf(path, sizeof(path), "%s/firstInstall", serverRoot);
	if (access(path, R_OK) == 0) {
		unlink(path);
		runBrowser("/firstInstall.html");
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start the user's default browser
//

static void runBrowser(char *page)
{
	MprCmd*	cmd;
	char	cmdBuf[MPR_MAX_STRING];
	char	*path, *ipAddr;
	char	*pathArg;

	getBrowserPath(&path, MPR_MAX_STRING);

	ipAddr = server->getDefaultHost()->getName();
	pathArg = strstr(path, "\"%1\"");
	if (*page == '/') {
		page++;
	}

	if (pathArg == 0) {
		mprSprintf(cmdBuf, MPR_MAX_STRING, "%s \"http://%s/%s\"", path, 
			ipAddr, page);
	} else {
		*path = '\0';
		mprSprintf(cmdBuf, MPR_MAX_STRING, "%s \"http://%s/%s\"", path, 
			ipAddr, page);
	}

	cmd = new MprCmd();
	cmd->start(cmdBuf, 0);
	mprFree(path);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the path to run the user's default browser. Caller must free the 
//	return string.
// 

static int getBrowserPath(char **path, int max)
{
	mprAssert(path);

#if LINUX
	if (access("/usr/bin/htmlview", X_OK) == 0) {
		*path = mprStrdup("/usr/bin/htmlview");
		return 0;
	}
	if (access("/usr/bin/mozilla", X_OK) == 0) {
		*path = mprStrdup("/usr/bin/mozilla");
		return 0;
	}
	if (access("/usr/bin/konqueror", X_OK) == 0) {
		*path = mprStrdup("/usr/bin/knonqueror");
		return 0;
	}
	return MPR_ERR_CANT_ACCESS;

#endif
#if WIN
	char	cmd[MPR_MAX_STRING];
	char	*type;
	char	*cp;

	if (mprReadRegistry("HKEY_CLASSES_ROOT\\.htm", "", &type, 
			MPR_MAX_STRING) < 0) {
		return MPR_ERR_CANT_ACCESS;
	}

	mprSprintf(cmd, MPR_MAX_STRING,
		"HKEY_CLASSES_ROOT\\%s\\shell\\open\\command", type);
	mprFree(type);

	if (mprReadRegistry(cmd, "", path, max) < 0) {
		mprFree(cmd);
		return MPR_ERR_CANT_ACCESS;
	}

	for (cp = *path; *cp; cp++) {
		if (*cp == '\\') {
			*cp = '/';
		}
		*cp = tolower(*cp);
	}
#else
#endif
	return 0;
}

#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Simple file copy
//

static int copyFile(char *from, char *to)
{
	char	buf[MPR_BUFSIZE];
	int		ifd, ofd, len;

	if ((ifd = open(from, O_RDONLY)) < 0) {
		return MPR_ERR_CANT_OPEN;
	}
	if ((ofd = open(to, O_CREAT | O_TRUNC | O_WRONLY, 0664)) < 0) {
		close(ifd);
		return MPR_ERR_CANT_OPEN;
	}
	while ((len = read(ifd, buf, sizeof(buf))) > 0) {
		if (write(ofd, buf, len) != len) {
			close(ifd);
			close(ofd);
			return MPR_ERR_CANT_WRITE;
		}
	}
	if (len < 0) {
		close(ifd);
		close(ofd);
		return MPR_ERR_CANT_READ;
	}
	close(ifd);
	close(ofd);
	return 0;
}

#endif
////////////////////////////////////////////////////////////////////////////////
//
//	Security checks. Make sure we are staring with a safe environment
//

static int securityChecks(char *program)
{
#if MOB
#if LINUX
	char			dir[MPR_MAX_FNAME];
	struct stat		sbuf;
	uid_t			uid;

    uid = getuid();
    if (getpwuid(uid) == 0) {
        mprError(MPR_L, MPR_USER, "Bad user id: %d", uid);
        return MPR_ERR_BAD_STATE;
    }

	dir[sizeof(dir) - 1] = '\0';
    if (getcwd(dir, sizeof(dir) - 1) == NULL) {
        mprError(MPR_L, MPR_USER, "Can't get the current working directory");
        return MPR_ERR_BAD_STATE;
    }

    if (((stat(dir, &sbuf)) != 0) || !(S_ISDIR(sbuf.st_mode))) {
        mprError(MPR_L, MPR_USER, "Can't access directory: %s", dir);
        return MPR_ERR_BAD_STATE;
    }
    if ((sbuf.st_mode & S_IWOTH) || (sbuf.st_mode & S_IWGRP)) {
        mprError(MPR_L, MPR_USER, 
			"Security risk, directory %s is writable by others", dir);
    }

	//
	//	Should always convert the program name into a fully qualified path
	//	Otherwise this fails
	//
	if (*program == '/') {
		if (((lstat(program, &sbuf)) != 0) || (S_ISLNK(sbuf.st_mode))) {
			mprError(MPR_L, MPR_USER, "Can't access program: %s", program);
			return MPR_ERR_BAD_STATE;
		}
		if ((sbuf.st_mode & S_IWOTH) || (sbuf.st_mode & S_IWGRP)) {
			mprError(MPR_L, MPR_USER, 
				"Security risk, Program %s is writable by others", program);
		}
		if (sbuf.st_mode & S_ISUID) {
			mprError(MPR_L, MPR_USER, "Security risk, %s is setuid", program);
		}
		if (sbuf.st_mode & S_ISGID) {
			mprError(MPR_L, MPR_USER, "Security risk, %s is setgid", program);
		}
	}
#endif
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if !WIN
static void initSignals()
{
	struct sigaction	act;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = catchSignal;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (mp->isService()) {
		sigaction(SIGINT, &act, 0);
		sigaction(SIGQUIT, &act, 0);
	}
	sigaction(SIGTERM, &act, 0);
	signal(SIGPIPE, SIG_IGN);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Catch signals. Do a graceful shutdown.
//

static void catchSignal(int signo, siginfo_t *info, void *arg)
{
	char	filler[32];

	//
	//	Fix for GCC optimization bug on Linux
	//
	filler[0] = filler[sizeof(filler) - 1];

	mprLog(MPR_INFO, "Received signal %d\nExiting ...\n", signo);
	if (mp) {
		mp->terminate(1);
	}
}

#endif // !WIN
////////////////////////////////////////////////////////////////////////////////
//
//	Print the version information
//

static void printVersion()
{
	mprPrintf("%s: Version: %s\n", mp->getAppName(), BLD_VERSION);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Display the usage
//

static void printUsage(char *programName)
{
	mprFprintf(MPR_STDERR, "usage: %s [-cDkmTV] [-f configFile] [-l logSpec] "
		"[-r serverRootDir]\n\n",  programName);
	mprFprintf(MPR_STDERR, "Options:\n");
	mprFprintf(MPR_STDERR, "  -f configFile  Specify alternate config file\n");
	mprFprintf(MPR_STDERR, "  -c             Output the host configuration\n");
	mprFprintf(MPR_STDERR, "  -D             Debug mode. Disable timeouts\n");
	mprFprintf(MPR_STDERR, "  -k             Kill existing running http\n");
	mprFprintf(MPR_STDERR, "  -m             Output memory stats (debug)\n");
	mprFprintf(MPR_STDERR, "  -r serverRoot  Alternate Home directory\n");
	mprFprintf(MPR_STDERR, "  -T             Output log timestamps (debug)\n");
	mprFprintf(MPR_STDERR, "  -V             Output version information\n");
}

////////////////////////////////////////////////////////////////////////////////
//
//	Emergency memory failure handler. FUTURE -- add reboot code here
//	Need a -C rebootCount switch. Must set all this up first thing on booting
//	as we won't be able to get ram here.
//

static void memoryFailure(int askSize, int totalHeapMem, int limit)
{
	mprPrintf("Can't get %d bytes of memory\n", askSize);
	mprPrintf("Total heap is %d. Limit set to %d\n", totalHeapMem, limit);
	exit(8);
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
