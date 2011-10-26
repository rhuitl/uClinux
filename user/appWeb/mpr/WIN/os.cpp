///
///	@file 	WIN/os.cpp
/// @brief 	Linux support for the Mbedthis Portable Runtime
///
///	This file contains most of the Windows specific implementation required to
///	host the MPR.
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

#define		IN_MPR 1

#include	"mpr/mpr.h"

///////////////////////////// Forward Declarations /////////////////////////////

#if BLD_FEATURE_CGI_MODULE
static void	singleThreadedOutputData(void *data, MprTimer *tp);
static void	multiThreadedOutputData(void *data, MprTask *tp);
#endif

static char	*getHive(char *key, HKEY *root);

//////////////////////////////////// Code //////////////////////////////////////
//
//	Initialize the platform layer
// 

int Mpr::platformInitialize()
{
	WSADATA		wsaData;

	if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
		return -1;
	}

	umask(022);
	//
	//	This crashes the WIN CRT
	//
	//	putenv("IFS=\t ");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Terminate the platform layer
// 

int Mpr::platformTerminate()
{
	WSACleanup();
	return 0;
}


////////////////////////////////////////////////////////////////////////////////
//
//	Start any required platform services
// 

int Mpr::platformStart(int startFlags)
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Stop the platform services
// 

int Mpr::platformStop()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_DLL

int Mpr::loadDll(char *path, char *fnName, void *arg, void **handlePtr)
{
	MprEntryProc	fn;
	char			localPath[MPR_MAX_FNAME];
    void			*handle;
	char			*cp;
	int				rc;

	mprAssert(path && *path);
	mprAssert(fnName && *fnName);

	mprStrcpy(localPath, sizeof(localPath), path);
	for (cp = localPath; *cp; cp++) {
		if (*cp == '/') {
			*cp = '\\';
		}
	}
    if ((handle = GetModuleHandle(mprGetBaseName(localPath))) == 0) {
		if ((handle = LoadLibrary(localPath)) == 0) {
			mprLog(0, "Can't load %s\nReason: \"%d\"\n", path, mprGetOsError());
			return MPR_ERR_CANT_OPEN;
		}
    }

	if ((fn = (MprEntryProc) GetProcAddress((HINSTANCE) handle, fnName)) == 0) {
		FreeLibrary((HINSTANCE) handle);
		mprLog(0, "Can't load %s\nReason: can't find function \"%s\"\n", 
			localPath, fnName);
		return MPR_ERR_NOT_FOUND;
	}
	if ((rc = (fn)(arg)) < 0) {
		FreeLibrary((HINSTANCE) handle);
		return MPR_ERR_CANT_INITIALIZE;
	}
	mprLog(MPR_INFO, "Loading DLL %s\n", path);
	if (handlePtr) {
		*handlePtr = handle;
	}
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::unloadDll(void *handle)
{
	mprAssert(handle);
	FreeLibrary((HINSTANCE) handle);
}

#endif	// BLD_FEATURE_DLL
////////////////////////////////////////////////////////////////////////////////
//
//	Write the given message to the native O/S log. We change the message.
// 

void Mpr::writeToOsLog(char *message, int flags)
{
	HKEY		hkey;
	void		*event;
	long		errorType;
	char		buf[MPR_MAX_STRING], msg[MPR_MAX_STRING];
	char		logName[MPR_MAX_STRING];
	char		*lines[9];
	char		*cp, *value;
	int			type;
	ulong		exists;
	static int	once = 0;

	mprStrcpy(buf, sizeof(buf), message);
	cp = &buf[strlen(buf) - 1];
	while (*cp == '\n' && cp > buf) {
		*cp-- = '\0';
	}

	if (flags & MPR_INFO) {
		type = EVENTLOG_INFORMATION_TYPE;
		mprSprintf(msg, MPR_MAX_STRING, "%s information: ", 
			Mpr::getAppName());

	} else if (flags == MPR_WARN) {
		type = EVENTLOG_WARNING_TYPE;
		mprSprintf(msg, MPR_MAX_STRING, "%s warning: ", Mpr::getAppName());

	} else {
		type = EVENTLOG_ERROR_TYPE;
		mprSprintf(msg, MPR_MAX_STRING, "%s error: %d", Mpr::getAppName(), 
			GetLastError());
	}

	lines[0] = msg;
	lines[1] = buf;
	lines[2] = lines[3] = lines[4] = lines[5] = 0;
	lines[6] = lines[7] = lines[8] = 0;

	if (once == 0) {
		//	Initialize the registry
		once = 1;
		mprSprintf(logName, sizeof(logName), 
			"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s",
			Mpr::getAppName());
		hkey = 0;

		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, logName, 0, NULL, 0, 
				KEY_ALL_ACCESS, NULL, &hkey, &exists) == ERROR_SUCCESS) {

			value = "%SystemRoot%\\System32\\netmsg.dll";
			if (RegSetValueEx(hkey, "EventMessageFile", 0, REG_EXPAND_SZ, 
					(uchar*) value, strlen(value) + 1) != ERROR_SUCCESS) {
				RegCloseKey(hkey);
				return;
			}

			errorType = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | 
				EVENTLOG_INFORMATION_TYPE;
			if (RegSetValueEx(hkey, "TypesSupported", 0, REG_DWORD, 
					(uchar*) &errorType, sizeof(DWORD)) != ERROR_SUCCESS) {
				RegCloseKey(hkey);
				return;
			}
			RegCloseKey(hkey);
		}
	}

	event = RegisterEventSource(0, Mpr::getAppName());
	if (event) {
		//	
		//	3299 is the event number for the generic message in netmsg.dll.
		//	"%1 %2 %3 %4 %5 %6 %7 %8 %9" -- thanks Apache for the tip
		//
		ReportEvent(event, EVENTLOG_ERROR_TYPE, 0, 3299, NULL, 
			sizeof(lines) / sizeof(char*), 0, (LPCSTR*) lines, 0);
		DeregisterEventSource(event);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Kill another running MR instance
//

int Mpr::killMpr()
{
	HWND	hwnd;
	int		i;

	hwnd = FindWindow(getAppName(), getAppTitle());
	if (hwnd) {
		PostMessage(hwnd, WM_QUIT, 0, 0L);

		//
		//	Wait for up to ten seconds while winAppWeb exits
		//
		for (i = 0; hwnd && i < 100; i++) {
			mprSleep(100);
			hwnd = FindWindow(getAppName(), getAppTitle());
		}
		if (hwnd == 0) {
			return 0;
		}

	} else {
		mprError(MPR_L, MPR_USER, "Can't find %s to kill", getAppName());
	}
	return -1;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MprCmdService /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_CGI_MODULE
//
//	Create the run service
//

MprCmdService::MprCmdService()
{
	mutex = new MprMutex();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Terminate the run service
//

MprCmdService::~MprCmdService()
{
#if BLD_DEBUG
	if (cmdList.getNumItems() > 0) {
		mprError(MPR_L, MPR_LOG, "Exiting with %d run commands unfreed\n",
			cmdList.getNumItems());
	}
#endif
	delete mutex;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Nothing to do
//

int MprCmdService::start()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Stop all processes
//

int MprCmdService::stop()
{
	MprCmd		*rp, *nextp;

	lock();
	rp = (MprCmd*) cmdList.getFirst();
	while (rp) {
		nextp = (MprCmd*) cmdList.getNext(rp);
		if (!(rp->flags & MPR_CMD_DETACHED)) {
			rp->stop(0, MPR_TIMEOUT_STOP);
		}
		rp = nextp;
	}
	unlock();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Insert a new run command
//

void MprCmdService::insertCmd(MprCmd *rp)
{
	lock();
	cmdList.insert(rp);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Remove a run command
//

void MprCmdService::removeCmd(MprCmd *rp)
{
	lock();
	cmdList.remove(rp);
	unlock();
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprCmdFiles //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprCmdFiles::MprCmdFiles()
{
	int		i;

	//
	//	Easier to see when opens file if we initialize with -2
	//
	for (i = 0; i < MPR_CMD_MAX_FD; i++) {
		clientFd[i] = -2;
		serverFd[i] = -2;
		name[i] = 0;
	}
}

////////////////////////////////////////////////////////////////////////////////

MprCmdFiles::~MprCmdFiles()
{
	int		j, i, rc, err;

	for (i = 0; i < MPR_CMD_MAX_FD; i++) {
		if (clientFd[i] >= 0) {
			close(clientFd[i]);
			clientFd[i] = -1;
		}
		if (serverFd[i] >= 0) {
			close(serverFd[i]);
			serverFd[i] = -1;
		}
		if (name[i]) {
			//
			//	Windows seems to be very slow in cleaning up the child's
			//	hold on the standard I/O file descriptors. Despite having
			//	waited for the child to exit and having received exit status,
			//	this unlink sometimes still gets a sharing violation. Ugh !!!
			//	We need to retry here (for up to 60 seconds). Under extreme 
			//	load -- this may fail to unlink the file.
			//
			for (j = 0; j < 1000; j++) {
				rc = unlink(name[i]);
				if (rc == 0) {
					break;
				}
				err = GetLastError();
				mprSleep(60);
			}
			if (j == 1000) {
				mprLog(0, "File busy, failed to unlink %s\n", name[i]);
			}
			mprFree(name[i]);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MprCmd ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Create a run object to run a command
// 

MprCmd::MprCmd()
{
	int		i;

	cwd = 0;
	data = 0;
	exitStatus = -1;
	flags = 0;
	handler = 0;
	handle = 0;
	inUse = 1;
#if BLD_FEATURE_LOG
	log = new MprLogModule("cmd");
#endif
	mutex = new MprMutex();
	outputDataProc = 0;
	pid = -1;
	stoppingCond = 0;
	timer = 0;
	task = 0;
	waitFd = -2;

	for (i = 0; i < MPR_CMD_MAX_FD; i++) {
		files.clientFd[i] = -1;
		files.serverFd[i] = -1;
	}
	
	mpr->cmdService->insertCmd(this);
}

////////////////////////////////////////////////////////////////////////////////

bool MprCmd::dispose()
{
	lock();
	mprAssert(inUse > 0);

	if (flags & MPR_CMD_DISPOSED) {
		mprAssert(0);
		unlock();
		return 0;
	}

	flags |= MPR_CMD_DISPOSED;
	mprLog(5, log, "dispose: inUse %d, pid %d\n", inUse, pid);

	if (flags & MPR_CMD_RUNNING) {
		mprAssert(!(flags & MPR_CMD_WAITED));
		//
		//	Do our best to reap the child death. Forced kill and then wait
		//
		stop(1, 0);
		waitForChild(MPR_TIMEOUT_STOP);
	}

	if (--inUse == 0) {
		delete this;
		return 1;
	} else {
		unlock();
		return 0;
	}
}

////////////////////////////////////////////////////////////////////////////////

MprCmd::~MprCmd()
{
	mprLog(5, log, "~MprCmd: pid %d\n", pid);

	//
	//	All this should have been done already, but we play it safe and make
	//	sure everthing is cleaned up. Increment inuse to prevent stop() and
	//	waitForChild() calling us again.
	//
	inUse++;
	mprAssert(flags & MPR_CMD_DISPOSED);
	if (flags & MPR_CMD_RUNNING) {
		stop(1, 0);
		if (!(flags & MPR_CMD_WAITED)) {
			waitForChild(MPR_TIMEOUT_STOP);
		}
	}
	if (timer) {
		timer->dispose();
	} 
	if (task) {
		task->dispose();
	} 
	mpr->cmdService->removeCmd(this);
	mprFree(cwd);
#if BLD_FEATURE_LOG
	delete log;
#endif
	delete mutex;
	inUse--;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::makeStdio(char *prefix, int fileFlags)
{
	int		rc;

	if (fileFlags & MPR_CMD_PIPES) {
		rc = makeStdioPipes(prefix, fileFlags);
	} else {
		rc = makeStdioFiles(prefix, fileFlags);
	}
	flags |= MPR_CMD_STDIO_MADE;
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::makeStdioPipes(char *prefix, int fileFlags)
{
	SECURITY_ATTRIBUTES	clientAtt, serverAtt, *att;
	HANDLE				fileHandle;
	char				pipeBuf[MPR_MAX_FNAME];
	int					openMode, pipeMode, i, fdRead, fdWrite;

	openMode = PIPE_ACCESS_INBOUND;
#if FUTURE
	if (fileFlags & MPR_CMD_NON_BLOCK) {
		openMode |= FILE_FLAG_OVERLAPPED;
	}
#endif

	//
	//	The difference is server fds are not inherited by the child
	//
	memset(&clientAtt, 0, sizeof(clientAtt));
	clientAtt.nLength = sizeof(SECURITY_ATTRIBUTES);
	clientAtt.bInheritHandle = TRUE;

	memset(&serverAtt, 0, sizeof(serverAtt));
	serverAtt.nLength = sizeof(SECURITY_ATTRIBUTES);
	serverAtt.bInheritHandle = FALSE;


	fileFlags |= MPR_CMD_STDWAIT;

	for (i = 0; i < MPR_CMD_MAX_FD - 1; i++) {
		if ((fileFlags & (1 << (i + MPR_CMD_FD_SHIFT))) == 0) {
			continue;
		}
		att = (i == MPR_CMD_IN) ? &clientAtt : &serverAtt;
		mprMakeTempFileName(pipeBuf, sizeof(pipeBuf), "\\\\.\\pipe\\", 0);

		pipeMode = (i == MPR_CMD_OUT) ? PIPE_NOWAIT : 0;

		fileHandle = CreateNamedPipe(pipeBuf, openMode, 
			pipeMode, 1, 0, 65536, 1, att);
		fdRead = (int) _open_osfhandle((long) fileHandle, 0);

		att = (i != MPR_CMD_IN) ? &clientAtt : &serverAtt;
		fileHandle = CreateFile(pipeBuf, GENERIC_WRITE, 
			0, att, OPEN_EXISTING, openMode, 0);
		fdWrite = (int) _open_osfhandle((long) fileHandle, 0);

		if (fdRead < 0 || fdWrite < 0) {
			mprError(MPR_L, MPR_LOG, "Can't create stdio pipes. Err %d\n",
				mprGetOsError());
			mprAssert(0);
			return -1;
		}
		if (i == MPR_CMD_IN) {
			files.clientFd[i] = fdRead;
			files.serverFd[i] = fdWrite;
		} else {
			files.clientFd[i] = fdWrite;
			files.serverFd[i] = fdRead;
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::makeStdioFiles(char *prefix, int fileFlags)
{
	SECURITY_ATTRIBUTES	clientAtt, serverAtt, *att;
	HANDLE				fileHandle;
	char				path[MPR_MAX_FNAME];
	int					i, fdRead, fdWrite;

	memset(&clientAtt, 0, sizeof(clientAtt));
	clientAtt.nLength = sizeof(SECURITY_ATTRIBUTES);
	clientAtt.bInheritHandle = TRUE;

	memset(&serverAtt, 0, sizeof(serverAtt));
	serverAtt.nLength = sizeof(SECURITY_ATTRIBUTES);
	serverAtt.bInheritHandle = FALSE;

	for (i = 0; i < MPR_CMD_MAX_FD - 1; i++) {
		if ((fileFlags & (1 << (i + MPR_CMD_FD_SHIFT))) == 0) {
			continue;
		}

		mprMakeTempFileName(path, sizeof(path), prefix, 1);
		files.name[i] = mprStrdup(path);

		att = (i != MPR_CMD_IN) ? &clientAtt : &serverAtt;
		fileHandle = CreateFile(path, GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE, att, 
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		mprAssert(fileHandle);
		fdWrite = (int) _open_osfhandle((long) fileHandle, 0);

		att = (i == MPR_CMD_IN) ? &clientAtt : &serverAtt;
		fileHandle = CreateFile(path, GENERIC_READ, 
			FILE_SHARE_READ | FILE_SHARE_WRITE, att, 
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		mprAssert(fileHandle);
		fdRead = (int) _open_osfhandle((long) fileHandle, 0);

		if (fdRead < 0 || fdWrite < 0) {
			mprError(MPR_L, MPR_LOG, "Can't create stdio files\n");
			return -1;
		}
		if (i == MPR_CMD_IN) {
			files.clientFd[i] = fdRead;
			files.serverFd[i] = fdWrite;
		} else {
			files.clientFd[i] = fdWrite;
			files.serverFd[i] = fdRead;
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MprCmd::setCwd(char *fileName)
{
	char	dirBuf[MPR_MAX_FNAME];

	mprGetDirName(dirBuf, sizeof(dirBuf), fileName);
	cwd = mprStrdup(dirBuf);
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::start(char *cmd, int userFlags)
{
	char	**argv;
	int		rc;

	mprMakeArgv(0, cmd, &argv, 0);
	rc = start(argv[0], argv, 0, 0, 0, userFlags);
	mprFree(argv);
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start the command to run (stdIn and stdOut are named from the client's 
//	perspective)
//

int MprCmd::start(char *program, char **argv, char **envp, MprCmdProc fn, 
	void *fnData, int userFlags)
{
	PROCESS_INFORMATION	procInfo;
	STARTUPINFO			startInfo;
	char				dirBuf[MPR_MAX_FNAME];
	char				*envBuf, **ep, *cmdBuf, **ap, *destp, *cp, *dir;
	char				progBuf[MPR_MAX_STRING], *localArgv[2], *saveArg0;
	int					argc, i, len, inheritFiles;

	mprAssert(program);
	mprAssert(argv);

	flags &= ~(MPR_CMD_WAITED | MPR_CMD_RUNNING);
	flags |= (userFlags & MPR_CMD_USER_FLAGS);
	exitStatus = -1;

	mprStrcpy(progBuf, sizeof(progBuf), program);
	progBuf[sizeof(progBuf) - 1] = '\0';
	program = progBuf;

	//
	//	Sanitize the command line (program name only)
	//
	for (cp = program; *cp; cp++) {
		if (*cp == '/') {
			*cp = '\\';
		} else if (*cp == '\r' || *cp == '\n') {
			*cp = ' ';
		}
	}
	if (*program == '"') {
		if ((cp = strrchr(++program, '"')) != 0) {
			*cp = '\0';
		}
	}

	saveArg0 = argv[0];
	if (argv == 0) {
		argv = localArgv;
		argv[1] = 0;
	}
	argv[0] = program;

	//
	//	Determine the command line length and arg count
	//
	argc = 0;
	for (len = 0, ap = argv; *ap; ap++) {
		len += strlen(*ap) + 1 + 2;			// Space and possible quotes
		argc++;
	}
	cmdBuf = (char*) mprMalloc(len + 1);
	cmdBuf[len] = '\0';
	
	//
	//	Add quotes to all args that have spaces in them including "program"
	//
	destp = cmdBuf;
	for (ap = &argv[0]; *ap; ) {
		cp = *ap;
		if ((strchr(cp, ' ') != 0) && cp[0] != '\"') {
			*destp++ = '\"';
			strcpy(destp, cp);
			destp += strlen(cp);
			*destp++ = '\"';
		} else {
			strcpy(destp, cp);
			destp += strlen(cp);
		}
		if (*++ap) {
			*destp++ = ' ';
		}
	}
	*destp = '\0';
	mprAssert((int) strlen(destp) < (len - 1));
	mprAssert(cmdBuf[len] == '\0');
	argv[0] = saveArg0;

	envBuf = 0;
	if (envp) {
		for (len = 0, ep = envp; *ep; ep++) {
			len += strlen(*ep) + 1;
		}
		envBuf = (char*) mprMalloc(len + 2);		// Win requires two nulls
		destp = envBuf;
		for (ep = envp; *ep; ep++) {
			strcpy(destp, *ep);
			mprLog(6, log, "Set CGI variable: %s\n", destp);
			destp += strlen(*ep) + 1;
		}
		*destp++ = '\0';
		*destp++ = '\0';						// WIN requires two nulls
	}
	
	memset(&startInfo, 0, sizeof(startInfo));
	startInfo.cb = sizeof(startInfo);

    startInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	if (flags & MPR_CMD_SHOW) {
		startInfo.wShowWindow = SW_SHOW;
	} else {
		startInfo.wShowWindow = SW_HIDE;
	}

	if (files.clientFd[MPR_CMD_IN] > 0) {
		startInfo.hStdInput = 
			(HANDLE) _get_osfhandle(files.clientFd[MPR_CMD_IN]);
	}
	if (files.clientFd[MPR_CMD_OUT] > 0) {
		startInfo.hStdOutput = 
			(HANDLE)_get_osfhandle(files.clientFd[MPR_CMD_OUT]);
	}
	if (files.clientFd[MPR_CMD_ERR] > 0) {
		startInfo.hStdError = 
			(HANDLE) _get_osfhandle(files.clientFd[MPR_CMD_ERR]);
	}

#if UNUSED
	SECURITY_ATTRIBUTES	secAtt;
	memset(&secAtt, 0, sizeof(secAtt));
	secAtt.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAtt.bInheritHandle = TRUE;
#endif

	if (userFlags & MPR_CMD_CHDIR) {
		if (cwd) {
			dir = cwd;
		} else {
			mprGetDirName(dirBuf, sizeof(dirBuf), argv[0]);
			dir = dirBuf;
		}
	} else {
		dir = 0;
	}

	inheritFiles = (flags & MPR_CMD_STDIO_MADE) ? 1 : 0;

	mprLog(5, log, "Running: %s\n", cmdBuf); 

	if (! CreateProcess(0, cmdBuf, 0, 0, inheritFiles, CREATE_NEW_CONSOLE,
			envBuf, dir, &startInfo, &procInfo)) {
		mprError(MPR_L, MPR_LOG, "Can't create process: %s, %d", 
			cmdBuf, mprGetOsError());
		return MPR_ERR_CANT_CREATE;
	}

	handle = (long) procInfo.hProcess;
	pid = procInfo.dwProcessId;

	if (procInfo.hThread != 0)  {
		CloseHandle(procInfo.hThread);
	}
	for (i = 0; i < MPR_CMD_MAX_FD; i++) {
		if (files.clientFd[i] >= 0) {
			close(files.clientFd[i]);
			files.clientFd[i] = -1;
		}
	}
	if (cmdBuf) {
		mprFree(cmdBuf);
	}
	if (envBuf) {
		mprFree(envBuf);
	}

	if (userFlags & MPR_CMD_WAIT) {
		waitForChild(INT_MAX);
		for (i = 0; i < MPR_CMD_MAX_FD; i++) {
			if (files.serverFd[i] >= 0) {
				close(files.serverFd[i]);
				files.serverFd[i] = -1;
			}
		}
		return exitStatus;
	}

	lock();
	outputDataProc = fn;
	data = fnData;
	flags |= MPR_CMD_RUNNING;

	if (1 || ! mpr->getAsyncSelectMode()) {
		timer = new MprTimer(MPR_TIMEOUT_CMD_WAIT, 
			singleThreadedOutputData, (void*) this);
#if FUTURE
		//
		//	Want non blocking reads if we are in single-threaded mode.
		//	Can't use this yet as we are holding a Request lock and so blocking
		//	in a read stops everything. Need proper Async I/O in windows.
		//
		if (mprGetMpr()->poolService->getMaxPoolThreads() == 0) {
		} else {
			task = new MprTask(multiThreadedOutputData, (void*) this);
			task->start();
		}
#endif
	}
	unlock();

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Force is ignored
//	Return -1 if timeout and command still running.
//	Return 0 if command is no-longer running.
//

int MprCmd::stop(bool force, int timeout)
{
	int		rc, start;

	mprLog(5, log, "stop: pid %d\n", pid);

	lock();
	if (!(flags & MPR_CMD_RUNNING)) {
		unlock();
		return 0;
	}
	inUse++;

	if (handle) {
		TerminateProcess((HANDLE) handle, 2);
	}
	while (timeout > 0 && (flags & MPR_CMD_RUNNING)) {
		if (stoppingCond == 0) {
			stoppingCond = new MprCond();
		}
		start = mprGetTime(0);
		unlock();
		stoppingCond->waitForCond(timeout);
		lock();
		timeout -= mprGetTime(0) - start;
	}

	if (stoppingCond) {
		delete stoppingCond;
		stoppingCond = 0;
	}

	rc = (flags & MPR_CMD_RUNNING) ? -1 : 0;
	if (--inUse == 0 && flags & MPR_CMD_DISPOSED) {
		delete this;
	} else {
		unlock();
	}
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

static void singleThreadedOutputData(void *data, MprTimer *tp)
{
	MprCmd		*rp;

	rp = (MprCmd*) data;
	rp->outputData(tp);
}

////////////////////////////////////////////////////////////////////////////////

static void multiThreadedOutputData(void *data, MprTask *tp)
{
	MprCmd		*rp;

	rp = (MprCmd*) data;
	rp->outputData();
}

////////////////////////////////////////////////////////////////////////////////
//
//	Process CGI output if single-threaded. The pipe is in non-blocking mode.
//

void MprCmd::outputData(MprTimer *tp)
{
	lock();
	inUse++;
	unlock();

	mprAssert(handle != 0);
	if (outputDataProc) {
		(outputDataProc)(this, data);
	}

	lock();
	if (--inUse == 0 && flags & MPR_CMD_DISPOSED) {
		delete this;
	} else {
		if (timer) {
			tp->reschedule();
		}
		unlock();
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Process CGI output data if multi-threaded. The pipe is in blocking mode
//	and we are using a pool thread. Keep reading until the command is complete.
//

void MprCmd::outputData()
{
	mprAssert(handle != 0);

	if (outputDataProc == 0) {
		return;
	}

	lock();
	inUse++;
	unlock();

	while (! (flags & MPR_CMD_DISPOSED)) {
		(outputDataProc)(this, data);
	}

	lock();
	if (--inUse == 0) {
		if (task) {
			task->dispose();
		}
		delete this;
	} else {
		unlock();
	}
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::getExitCode(int *status)
{
	mprAssert(status);

	lock();
	if (! (flags & MPR_CMD_WAITED)) {
		//
		//	May get EOF before process has actually exited. Nap for up to 5 sec
		//
		if (waitForChild(5000) < 0) {
			mprLog(5, log, "%d: getExitCode: pid %d\n", waitFd, pid);
			unlock();
			return MPR_ERR_NOT_READY;
		}
	}
	if (status) {
		*status = exitStatus;
	}
	unlock();

	mprLog(5, log, "%d: getExitCode: pid %d, code %d\n", waitFd, pid, *status);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::waitForChild(int timeout)
{
	int		rc;

	mprAssert(!(flags & MPR_CMD_WAITED));

	mprLog(5, log, "wait: pid %d\n", pid);

	lock();

	if ((rc = waitInner(timeout)) < 0) {
		mprLog(5, log, "%d: wait: failed: %d\n", waitFd, rc);
		unlock();
		mprAssert(0);
		return MPR_ERR_CANT_COMPLETE;
	}

	inUse++;
	flags &= ~MPR_CMD_RUNNING;
	if (stoppingCond) {
		stoppingCond->signalCond();
	}

	if (timer) {
		//
		//	No need to call timer->stop() as we are in a timer callback now
		//
		timer->dispose();
		timer = 0;
	}

	CloseHandle((HANDLE) handle);
	handle = 0;

	flags |= MPR_CMD_WAITED;

	mprLog(5, log, "wait: pid %d, inUse %d, flags %x\n", pid, inUse, flags);

	if (--inUse == 0 && flags & MPR_CMD_DISPOSED) {
		delete this;
	} else {
		unlock();
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::waitInner(int timeout)
{
	int		err, status;

	lock();
	if (handle == 0) {
		mprAssert(handle != 0);
		unlock();
		return 0;
	}

	if (timeout) {
		if (WaitForSingleObject((HANDLE) handle, timeout) != WAIT_OBJECT_0) {
			mprAssert(0);
			unlock();
			return MPR_ERR_TIMEOUT;
		}
	}

	do {
		if (GetExitCodeProcess((HANDLE) handle, (ulong*) &status) != 0) {
			if (status != STILL_ACTIVE) {
				mprLog(5, log, 
					"waitInner: pid %d, status %d\n", pid, status);
				exitStatus = status;
				unlock();
				return 0;
			} else {
				mprLog(5, log, 
					"waitInner: pid %d, still active\n", pid);
			}
		} else {
			err = GetLastError();
			mprAssert(0);
			unlock();
			return MPR_ERR_BAD_STATE;
		}
		//
		//	Seems we can wakeup from the wait and there still not be status
		//	pending
		//
		mprSleep(50);
	} while (timeout > 0);

	//	Should never get here 
	unlock();
	return MPR_ERR_TIMEOUT;
}

////////////////////////////////////////////////////////////////////////////////
//
//	The write fd is the commands input
//

int MprCmd::getWriteFd() 
{ 
	return files.serverFd[MPR_CMD_IN]; 
}

////////////////////////////////////////////////////////////////////////////////
//
//	The read fd is the commands output
//

int MprCmd::getReadFd() 
{
	return files.serverFd[MPR_CMD_OUT]; 
}

////////////////////////////////////////////////////////////////////////////////

void MprCmd::closeReadFd()
{
	if (files.serverFd[MPR_CMD_OUT] >= 0) {
		close(files.serverFd[MPR_CMD_OUT]);
		if (waitFd == files.serverFd[MPR_CMD_OUT]) {
			waitFd = -1;
		}
		files.serverFd[MPR_CMD_OUT] = -1;
	}
}

////////////////////////////////////////////////////////////////////////////////

void MprCmd::closeWriteFd()
{
	if (files.serverFd[MPR_CMD_IN] >= 0) {
		close(files.serverFd[MPR_CMD_IN]);
		files.serverFd[MPR_CMD_IN] = -1;
	}
}

#endif // BLD_FEATURE_CGI_MODULE
////////////////////////////////////////////////////////////////////////////////
extern "C" {

int mprGetRandomBytes(uchar *buf, int length, int block)
{
    HCRYPTPROV 		prov;
	int				rc;

	rc = 0;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 
			CRYPT_VERIFYCONTEXT | 0x40)) {
		return -mprGetOsError();
    }
    if (!CryptGenRandom(prov, length, buf)) {
    	rc = -mprGetOsError();
    }
    CryptReleaseContext(prov, 0);
    return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Read a registry value
// 

int mprReadRegistry(char *key, char *name, char **buf, int max)
{
	HKEY		top, h;
	char		*value;
	ulong		type, size;

	mprAssert(key && *key);
	mprAssert(buf);

	//
	//	Get the registry hive
	// 
	if ((key = getHive(key, &top)) == 0) {
		return MPR_ERR_CANT_ACCESS;
	}

	if (RegOpenKeyEx(top, key, 0, KEY_READ, &h) != ERROR_SUCCESS) {
		return MPR_ERR_CANT_ACCESS;
	}

	//
	//	Get the type
	// 
	if (RegQueryValueEx(h, name, 0, &type, 0, &size) != ERROR_SUCCESS) {
		RegCloseKey(h);
		return MPR_ERR_CANT_READ;
	}
	if (type != REG_SZ && type != REG_EXPAND_SZ) {
		RegCloseKey(h);
		return MPR_ERR_BAD_TYPE;
	}

	value = (char*) mprMalloc(size);
	if ((int) size > max) {
		RegCloseKey(h);
		return MPR_ERR_WONT_FIT;
	}
	if (RegQueryValueEx(h, name, 0, &type, (uchar*) value, &size) != 
			ERROR_SUCCESS) {
		delete value;
		RegCloseKey(h);
		return MPR_ERR_CANT_READ;
	}

    RegCloseKey(h);
	*buf = value;
	return 0;
}

} // extern "C"
////////////////////////////////////////////////////////////////////////////////
//
//	Determine the registry hive by the first portion of the path. Return 
//	a pointer to the rest of key path after the hive portion.
// 

static char *getHive(char *keyPath, HKEY *hive)
{
	char	key[MPR_MAX_STRING], *cp;
	int		len;

	mprAssert(keyPath && *keyPath);

	*hive = 0;

	mprStrcpy(key, sizeof(key), keyPath);
	key[sizeof(key) - 1] = '\0';

	if (cp = strchr(key, '\\')) {
		*cp++ = '\0';
	}
	if (cp == 0 || *cp == '\0') {
		return 0;
	}

	if (!mprStrCmpAnyCase(key, "HKEY_LOCAL_MACHINE")) {
		*hive = HKEY_LOCAL_MACHINE;
	} else if (!mprStrCmpAnyCase(key, "HKEY_CURRENT_USER")) {
		*hive = HKEY_CURRENT_USER;
	} else if (!mprStrCmpAnyCase(key, "HKEY_USERS")) {
		*hive = HKEY_USERS;
	} else if (!mprStrCmpAnyCase(key, "HKEY_CLASSES_ROOT")) {
		*hive = HKEY_CLASSES_ROOT;
	} else {
		mprError(MPR_L, MPR_LOG, "Bad hive key: %s", key);
	}

	if (*hive == 0) {
		return 0;
	}
	len = strlen(key) + 1;
	return keyPath + len;
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
