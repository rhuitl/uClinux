///
///	@file 	LINUX/os.cpp
/// @brief 	Linux support for the Mbedthis Portable Runtime
///
///	This file contains most of the LINUX specific implementation required to
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

#define 	IN_MPR	1

#include	"mpr/mpr.h"

////////////////////////////// Forward Declarations ////////////////////////////

static pid_t	readPid();
static void		writePid();

#if BLD_FEATURE_CGI_MODULE
static int		runOutputData(void *data, int mask, int isMprPoolThread);
#if LINUXTHREADS
static void 	(*chainFunc)(int signo, siginfo_t *info, void *arg);
#endif
#endif

//////////////////////////////////// Code //////////////////////////////////////
//
//	Initialize the platform layer
//

int Mpr::platformInitialize()
{
#if UNUSED
	//
	//	Changing the runas user is currently done in http
	//	FUTURE: move into the MPR
	//
	if (geteuid() != 0) {
		mprError(MPR_L, MPR_USER, "Insufficient privilege");
		return -1;
	}
#endif
	
	umask(022);
	putenv("IFS=\t ");

#if FUTURE
	// 
	//	Open a syslog connection
	//
	openlog(mpr->getAppName(), LOG_CONS || LOG_PERROR, LOG_LOCAL0);
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Terminate the platform layer
//

int Mpr::platformTerminate()
{
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start any required platform services
//

int Mpr::platformStart(int startFlags)
{
	if (startFlags & MPR_KILLABLE) {
		writePid();
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Stop the platform services
//

int Mpr::platformStop()
{
	char	pidPath[MPR_MAX_FNAME];

	mprSprintf(pidPath, MPR_MAX_FNAME, "%s/.%s_pid.log", 
		getInstallDir(), getAppName());
	unlink(pidPath);

	return 0;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_DLL
#if MACOSX

int Mpr::loadDll(char *path, char *fnName, void *arg, void **handlePtr)
{
	NSObjectFileImageReturnCode returnCode;
	NSObjectFileImage 	fileImage;
	NSModule 			handle;
	MprEntryProc		fn;
	NSLinkEditErrors 	c;
	const char 			*fileName;
	const char 			*errorString;
	char				symName[ mprStrlen( fnName, MPR_MAX_FNAME ) + 2 ];
	int					rc;
	int 				errorNumber;

	mprAssert(path && *path);
	mprAssert(fnName && *fnName);

	errorString = 0;

	mprSprintf(symName, sizeof(symName), "_%s", fnName);
	returnCode = NSCreateObjectFileImageFromFile(path, &fileImage);

	// RTLD | RTLD_GLOBAL !!!
	if (returnCode == NSObjectFileImageSuccess) {
	    handle = NSLinkModule(fileImage,path, 
			NSLINKMODULE_OPTION_RETURN_ON_ERROR | NSLINKMODULE_OPTION_BINDNOW );
	    NSDestroyObjectFileImage(fileImage);

	    if (handle) {
			NSSymbol nssym = NSLookupSymbolInModule(handle, symName);
			void *address = NSAddressOfSymbol(nssym);

			if ((fn = (MprEntryProc) address) == 0) {
				mprLog(0, "Can't load %s\n"
					"Reason: can't find function \"%s\"\n", path, symName);
				NSUnLinkModule(handle, 0);
				return MPR_ERR_NOT_FOUND;
			}

			if ((rc = (fn)(arg)) < 0) {
				NSUnLinkModule(handle, 0);
				return MPR_ERR_CANT_INITIALIZE;
			}

			mprLog(MPR_INFO, "Loading DLL %s\n", path);
			if (handlePtr) {
				*handlePtr = handle;
			}
			return rc;

		} else {
			NSLinkEditError(&c, &errorNumber, &fileName, &errorString);
			mprLog(0, "Can't load %s\nReason: \"%s\"\n", path, errorString);
			return MPR_ERR_CANT_OPEN;
		}

	} else {
		NSLinkEditError(&c, &errorNumber, &fileName, &errorString);
		mprLog(0, "Can't load %s\nReason: \"%s\"\n", path, errorString);
		return MPR_ERR_CANT_OPEN;
	}
}

////////////////////////////////////////////////////////////////////////////////

void Mpr::unloadDll(void *handle)
{
	mprAssert(handle);
	NSUnLinkModule(handle, 0);
}

////////////////////////////////////////////////////////////////////////////////
#else	// !MACOSX

int Mpr::loadDll(char *path, char *fnName, void *arg, void **handlePtr)
{
	MprEntryProc	fn;
	void			*handle;
	int				rc;

	mprAssert(path && *path);
	mprAssert(fnName && *fnName);

	if ((handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL)) == 0) {
		mprError(MPR_L, MPR_LOG, "Can't load %s\nReason: \"%s\"\n", 
			path, dlerror());
		return MPR_ERR_CANT_OPEN;
	}

	if ((fn = (MprEntryProc) dlsym(handle, fnName)) == 0) {
		mprError(MPR_L, MPR_LOG, 
			"Can't load %s\nReason: can't find function \"%s\"\n", 
			path, fnName);
		dlclose(handle);
		return MPR_ERR_NOT_FOUND;
	}
	if ((rc = (fn)(arg)) < 0) {
		dlclose(handle);
		return rc;
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
	dlclose(handle);
}

#endif // !MACOSX
#endif	// BLD_FEATURE_DLL
////////////////////////////////////////////////////////////////////////////////
//	
//	Write a message in the O/S native log (syslog in the case of LINUX)
//

void Mpr::writeToOsLog(char *message, int flags)
{
#if FUTURE
	//
	//	This bloats memory a lot
	//
	char	msg[MPR_MAX_FNAME];

	if (flags & MPR_INFO) {
		mprSprintf(msg, sizeof(msg), "%s information: ", mpr->getAppName());

	} else if (flags & MPR_WARN) {
		mprSprintf(msg, sizeof(msg), "%s warning: ", mpr->getAppName());

	} else {
		mprSprintf(msg, sizeof(msg), "%s error: ", mpr->getAppName());
	}
	syslog(flags, "%s: %s\n", msg, message);
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Kill another running MR instance
//

int Mpr::killMpr()
{
	pid_t	pid;

	pid = readPid();
	if (pid < 0) {
		return MPR_ERR_NOT_FOUND;
	}

	mprLog(MPR_INFO, "Sending signal %d to process %d\n", SIGTERM, pid);
	if (kill(pid, SIGTERM) < 0) {
		if (errno == ESRCH) {
			mprLog(MPR_INFO, "Pid %d is not valid\n", pid);
		} else {
			mprLog(MPR_INFO, "Call to kill(%d) failed, %d\n", pid, errno);
		}
		return MPR_ERR_CANT_COMPLETE;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get the pid for the current MR process
//

static pid_t readPid()
{
	char	pidPath[MPR_MAX_FNAME];
	pid_t	pid;
	int		fd;

	mprSprintf(pidPath, MPR_MAX_FNAME, "%s/.%s_pid.log", 
		mpr->getInstallDir(), mpr->getAppName());

	if ((fd = open(pidPath, O_RDONLY, 0666)) < 0) {
		mprLog(MPR_DEBUG, "Could not read a pid from %s\n", pidPath);
		return -1;
	}
	if (read(fd, &pid, sizeof(pid)) != sizeof(pid)) {
		mprLog(MPR_DEBUG, "Read from file %s failed\n", pidPath);
		close(fd);
		return -1;
	}
	close(fd);
	return pid;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Write the pid for the current MR
// 

static void writePid()
{
	char	pidPath[MPR_MAX_FNAME];
	pid_t	pid;
	int		fd;

	mprSprintf(pidPath, MPR_MAX_FNAME, "%s/.%s_pid.log", 
		mpr->getInstallDir(), mpr->getAppName());

	if ((fd = open(pidPath, O_CREAT | O_RDWR | O_TRUNC, 0666)) < 0) {
		mprLog(MPR_INFO, "Could not create pid file %s\n", pidPath);
		return;
	}
	pid = getpid();
	if (write(fd, &pid, sizeof(pid)) != sizeof(pid)) {
		mprLog(MPR_WARN, "Write to file %s failed\n", pidPath);
	}
	close(fd);
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
#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
#if LINUXTHREADS
	initSignals();
#endif
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
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

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
		if ((rp->flags & MPR_CMD_RUNNING) && 
				!(rp->flags & MPR_CMD_DETACHED)) {
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
#if LINUXTHREADS
//
//	Catch child death signals and chain to any previous handler.
//	We actually reap the child process remenants here.
//

static void childDeath(int signo, siginfo_t *info, void *arg)
{
	int		pid, rc, status;

	mprAssert(signo == SIGCHLD && info);

	if (info) {
		if (info->si_code == CLD_EXITED || info->si_code == CLD_KILLED) {
			pid = info->si_pid;
			status = info->si_status;
			rc = waitpid(pid, 0, WNOHANG | __WALL);
			mprAssert(rc == pid);
			mprGetMpr()->getCmdService()->processSignal(pid, status);
			mprLog(6, "Child exit pid %d, status %d\n", pid, status);
		}
	}
	if (chainFunc) {
		(*chainFunc)(signo, info, arg);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Linuxthreads will create threads with a different thread id. This
//	means the new thread cannot call waitForChild(). This affects
//	uClibc. NPTL in glibc does not have this problem. Solution is to
//	have the caller wait here until the handler calls getExitCode.
//	This will wake us up and we can get the exit code for it.
//

void MprCmdService::initSignals()
{
	struct sigaction	act, old;

	memset(&act, 0, sizeof(act));

	act.sa_sigaction = childDeath;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_NOCLDSTOP | SA_RESTART | SA_SIGINFO;

	if (sigaction(SIGCHLD, &act, &old) < 0) {
		mprError(MPR_L, MPR_USER, "Can't initialize signals\n");
	}
	chainFunc = old.sa_sigaction;
}

////////////////////////////////////////////////////////////////////////////////

void MprCmdService::processSignal(int pid, int status)
{
	MprCmd		*rp;

	lock();
	rp = (MprCmd*) cmdList.getFirst();
	while (rp) {
		if (rp->getPid() == pid) {
			rp->setExitStatus(status);
			unlock();
			return;
		}
		rp = (MprCmd*) cmdList.getNext(rp);
	}
	unlock();
	mprError(MPR_L, MPR_LOG, "CmdService can't find child pid %d\n", pid);
}

#endif
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
	int		i;

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
			unlink(name[i]);
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
#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
	stoppingCond = 0;
#endif
	outputDataProc = 0;
	pid = -1;
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
	mprLog(8, log, "%d: dispose: inUse %d, pid %d\n", waitFd, inUse, pid);

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
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MprCmd::~MprCmd()
{
	mprLog(8, log, "%d: ~MprCmd: pid %d\n", waitFd, pid);

	//
	//	All this should have been done already, but we play it safe and make
	//	sure everthing is cleaned up. Increment inuse to prevent stop() and
	//	wait calling us again.
	//
	inUse++;
	mprAssert(flags & MPR_CMD_DISPOSED);
	if (flags & MPR_CMD_RUNNING) {
		stop(1, 0);
		if (!(flags & MPR_CMD_WAITED)) {
			waitForChild(MPR_TIMEOUT_STOP);
		}
	}
	if (handler) {
		handler->dispose();
	}
	mpr->cmdService->removeCmd(this);
	mprFree(cwd);

#if BLD_FEATURE_LOG
	delete log;
#endif
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
	inUse--;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::makeStdio(char *prefix, int fileFlags)
{
	int		rc;

	mprLog(7, log, "makeStdio: prefix %s, flags %x\n", prefix, fileFlags);
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
	int		fds[2];
	int		i;

	fileFlags |= MPR_CMD_STDWAIT;

	for (i = 0; i < MPR_CMD_MAX_FD; i++) {
		if ((fileFlags & (1 << (i + MPR_CMD_FD_SHIFT))) == 0) {
			continue;
		}
		if (i == MPR_CMD_WAITFD && files.serverFd[MPR_CMD_OUT] >= 0) {
			continue;
		}
		if (pipe(fds) < 0) {
			mprError(MPR_L, MPR_LOG, "Can't create stdio pipes. Err %d\n",
				mprGetOsError());
			mprAssert(0);
			return -1;
		}
		if (i == MPR_CMD_IN) {
			files.clientFd[i] = fds[0];
			files.serverFd[i] = fds[1];
		} else {
			files.clientFd[i] = fds[1];
			files.serverFd[i] = fds[0];
		}
		mprLog(7, log, "makeStdio: pipe handles[%d] read %d, write %d\n",
			i, fds[0], fds[1]);
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::makeStdioFiles(char *prefix, int fileFlags)
{
	char	path[MPR_MAX_FNAME];
	int		i, fdRead, fdWrite;

	fileFlags |= MPR_CMD_STDWAIT;

	for (i = 0; i < MPR_CMD_MAX_FD; i++) {
		if ((fileFlags & (1 << (i + MPR_CMD_FD_SHIFT))) == 0) {
			continue;
		}
		if (i < MPR_CMD_WAITFD) {
			mprMakeTempFileName(path, sizeof(path), prefix, 1);
			files.name[i] = mprStrdup(path);
			fdWrite = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
			fdRead = open(path, O_RDONLY);
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
			mprLog(7, log, "makeStdio: file handles[%d] read %d, write %d\n",
				i, fdRead, fdWrite);
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MprCmd::setCwd(char *dir)
{
	mprFree(cwd);
	cwd = mprStrdup(dir);
}

////////////////////////////////////////////////////////////////////////////////
//
//	It would be nice if you could issue multiple start() commands on a single
//	object (serially), however it is very doubtful if this currently works.
//

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
	char	dir[MPR_MAX_FNAME];
	int		i, err, fds[2];

	mprLog(4, log, "start: %s\n", program);
	flags &= ~(MPR_CMD_WAITED | MPR_CMD_RUNNING);
	flags |= (userFlags & MPR_CMD_USER_FLAGS);
	exitStatus = -1;

	if (files.serverFd[MPR_CMD_OUT] >= 0 && files.name[MPR_CMD_OUT] == 0) {
		waitFd = files.serverFd[MPR_CMD_OUT];
	} else {
		waitFd = files.serverFd[MPR_CMD_WAITFD];
	}
	if (waitFd < 0) {
		//
		//	Make a pipe just so we can signal child death
		//
		if (pipe(fds) < 0) {
			mprError(MPR_L, MPR_LOG, "Can't create pipes to run %s\n", program);
			return MPR_ERR_CANT_OPEN;
		}
		waitFd = files.serverFd[MPR_CMD_WAITFD] = fds[0];
		files.clientFd[MPR_CMD_WAITFD] = fds[1];

		mprLog(7, log, "start: wait pipe read %d, write %d\n", fds[0], fds[1]);
	} 
	mprAssert(waitFd >= 0);

#if UNUSED
	if (flags & MPR_CMD_NON_BLOCK) {
		fcntl(waitFd, F_SETFL, fcntl(waitFd, F_GETFL) | O_NONBLOCK);
	}
#endif

	mprAssert(program != 0);
	mprAssert(argv != 0);

	mprLog(6, log, "start: %s\n", program);
	for (i = 0; argv[i]; i++) {
		mprLog(6, log, "    arg[%d]: %s\n", i, argv[i]);
	}
	if (envp) {
		for (i = 0; envp[i]; i++) {
			mprLog(6, log, "    envp[%d]: %s\n", i, envp[i]);
		}
	}

	if (access(program, X_OK) < 0) {
		mprLog(5, log, "start: can't access %s, errno %d\n", 
			program, mprGetOsError());
		return MPR_ERR_CANT_ACCESS;
	}

#if LINUXTHREADS
	sigset_t	set, old;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);

#if BLD_FEATURE_MULTITHREAD
	pthread_sigmask(SIG_BLOCK, &set, &old);
#else
	sigprocmask(SIG_BLOCK, &set, &old);
#endif

	pid = fork();

#if BLD_FEATURE_MULTITHREAD
	pthread_sigmask(SIG_SETMASK, &old, 0);
#else
	sigprocmask(SIG_SETMASK, &old, 0);
#endif
#else

	pid = fork();
#endif

	if (pid < 0) {
		mprLog(0, log, "Can't for a new process to run %s\n", program);
		return MPR_ERR_CANT_INITIALIZE;

	} else if (pid == 0) {
		//
		//	Child
		//
		umask(022);
		if (flags & MPR_CMD_NEW_SESSION) {
			setsid();
		}
		if (flags & MPR_CMD_CHDIR) {
			if (cwd) {
				chdir(cwd);
			} else {
				mprGetDirName(dir, sizeof(dir), program);
				chdir(dir);
			}
		}

		//	
		//	FUTURE -- could chroot as a security feature (perhaps cgi-bin)
		//
		i = 0;
		for (; i < 3; i++) {
			if (files.clientFd[i] >= 0) {
				dup2(files.clientFd[i], i);
			} else {
				close(i);
			}
		}

		//
		//	FUTURE -- need to get a better max file limit than this
		//
		for (; i < 128; i++) {
			if (i != files.clientFd[MPR_CMD_WAITFD]) {
				close(i);
			}
		}

		if (envp) {
			execve(program, argv, envp);
		} else {
			execv(program, argv);
		}
		err = errno;
		getcwd(dir, sizeof(dir));
		mprStaticPrintf("Can't exec %s, err %d, cwd %d\n", program, err, dir);
		mprAssert(0);
		exit(-(MPR_ERR_CANT_INITIALIZE));

	} else {
		for (i = 0; i < MPR_CMD_MAX_FD; i++) {
			if (files.clientFd[i] >= 0) {
				close(files.clientFd[i]);
				files.clientFd[i] = -1;
			}
		}

		mprLog(7, log, "%d: start: child pid %d\n", waitFd, pid);
		data = fnData;

		if (flags & MPR_CMD_WAIT) {
			if (waitForChild(INT_MAX) < 0) {
				mprLog(2, log, "%d: start: wait error\n", waitFd);
			}
			for (i = 0; i < MPR_CMD_MAX_FD; i++) {
				if (files.serverFd[i] >= 0) {
					close(files.serverFd[i]);
					files.serverFd[i] = -1;
				}
			}
			return exitStatus;
		}
		if (flags & MPR_CMD_DETACHED) {
			return 0;
		}

		lock();
		outputDataProc = fn;
		flags |= MPR_CMD_RUNNING;
		//
		//	Setup a read handler on server handle for the clients stdout
		//
		mprAssert(waitFd >= 0);
		fcntl(waitFd, F_SETFL, fcntl(waitFd, F_GETFL) | O_NONBLOCK);
		handler = new MprSelectHandler(waitFd, MPR_READABLE, 
			(MprSelectProc) runOutputData, (void*) this, MPR_NORMAL_PRIORITY);
		unlock();
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return -1 if timeout and command still running.
//	Return 0 if command is no-longer running.
//

int MprCmd::stop(bool force, int timeout)
{
	int		rc;

	mprLog(7, log, "%d: stop: pid %d\n", waitFd, pid);
	lock();
	if (!(flags & MPR_CMD_RUNNING)) {
		unlock();
		return 0;
	}
	inUse++;

	if (pid > 0) {
		kill(pid, (force) ? SIGKILL: SIGTERM);
	}
#if BLD_FEATURE_MULTITHREAD
	while (timeout > 0 && (flags & MPR_CMD_RUNNING)) {
		int		start;
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
#endif

	rc = (flags & MPR_CMD_RUNNING) ? -1 : 0;
	if (--inUse == 0 && flags & MPR_CMD_DISPOSED) {
		delete this;
	} else {
		unlock();
	}
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Control handler. This will get an I/O event when the child exits.
//

static int runOutputData(void *data, int mask, int isMprPoolThread)
{
	MprCmd			*rp;

	mprAssert(mask & MPR_READABLE);
	rp = (MprCmd*) data;
	rp->outputData();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void MprCmd::outputData()
{
	if (outputDataProc) {
		(outputDataProc)(this, data);

	} else {
		char	buf[256];
		int		exitCode;

		//
		//	Read all data available
		//
		while (read(getReadFd(), buf, sizeof(buf)) > 0) {
			;
		}
		getExitCode(&exitCode);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Windows handler when using files.
//

void MprCmd::outputData(MprTimer *tp)
{
}


////////////////////////////////////////////////////////////////////////////////

int MprCmd::getExitCode(int *status)
{
	mprAssert(status);

	lock();
	if (! (flags & MPR_CMD_WAITED)) {
		if (waitForChild(10000) < 0) {
			mprLog(5, log, "%d: getExitCode: pid %d\n", waitFd, pid);
			unlock();
			return MPR_ERR_NOT_READY;
		}
	}
	if (status) {
		*status = exitStatus;
	}
	unlock();

	mprLog(7, log, "%d: getExitCode: pid %d, code %d\n", waitFd, pid, *status);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::waitForChild(int timeout)
{
	int		rc;

	mprAssert(!(flags & MPR_CMD_WAITED));

	mprLog(7, log, "%d: cleanup: pid %d\n", waitFd, pid);

	lock();
	if ((rc = waitInner(timeout)) < 0) {
		mprLog(2, log, "%d: wait: failed: %d\n", waitFd, rc);
		unlock();
		mprAssert(0);
		return MPR_ERR_CANT_COMPLETE;
	}

	inUse++;
	flags &= ~MPR_CMD_RUNNING;

#if BLD_FEATURE_MULTITHREAD
	if (stoppingCond) {
		stoppingCond->signalCond();
	}
#endif

	if (handler) {
		//
		//	Can't do a stop() here because we are being called from 
		//	within a select handler. Use delayed close (below) to ensure
		//	the handle we are waiting on does not get reused by anyone 
		//	prematurely.
		//
		if (waitFd >= 0) {
			mprAssert(waitFd == handler->getFd());
			handler->setCloseOnDispose();
		}
		handler->dispose();
		handler = 0;

	} else if (waitFd >= 0) {
		close(waitFd);
	}

	if (waitFd >= 0) {
		if (waitFd == files.serverFd[MPR_CMD_OUT]) {
			files.serverFd[MPR_CMD_OUT] = -1;
		} else {
			files.serverFd[MPR_CMD_WAITFD] = -1;
		}
	}

	flags |= MPR_CMD_WAITED;

	mprLog(8, log, "wait: pid %d, inUse %d, flags %x\n", pid, inUse, flags);

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
	int		rc, start;

	lock();
	if (pid < 0) {
		unlock();
		return MPR_ERR_BAD_STATE;
	}

	rc = -1;
	start = mprGetTime(0);
	do {
#if LINUXTHREADS
		if (exitStatus != -1) {
			rc = pid;
			break;
		}
#else
		{
			int		status;

			rc = waitpid(pid, &status, WNOHANG | __WALL);
			if (rc < 0) {
				if (errno != EINTR) {
					mprLog(2, log, 
						"%d: waitInner: waitpid error, pid %d, errno %d\n", 
						waitFd, pid, errno);
					return MPR_ERR_BUSY;
				}
			} else if (rc > 0) {
				exitStatus = WEXITSTATUS(status);
				break;
			}
		}
#endif
		mprSleep(50);

	} while ((mprGetTime(0) - start) < timeout || mprGetDebugMode());

	if (rc == pid) {
		mprLog(5, log, "%d: waitInner: pid %d, exit status %d\n", 
			waitFd, pid, exitStatus);
		pid = -1;
		unlock();
		return 0;
	}

	mprLog(7, log, "%d: waitInner: rc %d, errno %d, timeout pid %d\n", 
		rc, errno, waitFd, pid);

	unlock();
	return MPR_ERR_TIMEOUT;
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::getWriteFd() 
{ 
	return files.serverFd[MPR_CMD_IN]; 
}

////////////////////////////////////////////////////////////////////////////////

int MprCmd::getReadFd() 
{
	return files.serverFd[MPR_CMD_OUT]; 
}

////////////////////////////////////////////////////////////////////////////////

void MprCmd::closeReadFd()
{
	lock();
	if (files.serverFd[MPR_CMD_OUT] >= 0) {
		if (waitFd == files.serverFd[MPR_CMD_OUT]) {
			mprAssert(waitFd == handler->getFd());
			handler->setCloseOnDispose();
			waitFd = -1;
		} else {
			close(files.serverFd[MPR_CMD_OUT]);
		}
		files.serverFd[MPR_CMD_OUT] = -1;
	}
	unlock();
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

#if BLD_DEBUG
//
//	Useful in tracking down file handle leaks
//

void mprNextFds(char *msg)
{
	int i, fds[4];

	mprLog(0, msg);
	for (i = 0; i < 4; i++) {
		fds[i] = open("mob.txt", O_CREAT | O_TRUNC, 0666);
		mprLog("Next Fds %d\n", fds[i]);
	}
	for (i = 0; i < 4; i++) {
		close(fds[i]);
	}
}
#endif
////////////////////////////////////////////////////////////////////////////////
extern "C" {

int mprGetRandomBytes(uchar *buf, int length, int block)
{
	int		fd, sofar, rc;

	fd = open((block) ? "/dev/random" : "/dev/urandom", O_RDONLY, 0666);
	if (fd < 0) {
		mprAssert(0);
		return MPR_ERR_CANT_OPEN;
	}

	sofar = 0;
	do {
		rc = read(fd, &buf[sofar], length);
		if (rc < 0) {
			mprAssert(0);
			return MPR_ERR_CANT_READ;
		}
		length -= rc;
		sofar += rc;
	} while (length > 0);
	close(fd);
	return 0;
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
