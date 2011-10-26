///
///	@file 	winAppWeb.cpp
/// @brief 	Windows AppWeb main program
///
///	The Windows appWeb main program can be invoked manually or run as a service.
///	While the console main.cpp can also be used on windows, mainWin.cpp will 
///	provide higher performance due to its use of the Windows message event
///	loop rather than select.
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
#if WIN

#define	IN_HTTP_LIBRARY 1

#include	"appWeb.h"

//////////////////////////////////// Locals ////////////////////////////////////

static Mpr			*mp;				// Global MPR object
static HINSTANCE	appInst;			// Current application instance 
static HWND			appHwnd;			// Application window handle 
static int			isService;			// Running as a service
static HWND			otherHwnd;			// Existing instance window handle 
static int			serviceOp;			// Service operation
static HANDLE		serviceWaitEvent;	// Service event to block on 
static HMENU		subMenu;			// As the name says
static HMENU		trayMenu;			// As the name says
static HANDLE		threadHandle;		// Handle for the service thread
static MprTimer		*trayTimer;			// Timer to display the tray icon
static char			*cmdSpec = "cdDf:gi:kl:mp:r:suTV";
static char			*serverRoot;		// Directory to find appWeb.conf
static int			trayIcon = 1;		// Icon in the tray
static int			taskBarIcon = 0;	// Icon in the task bar
static MaServer		*server;			// Default server

//
//	Windows message defines
//
#define MPR_HTTP_TRAY_MESSAGE		WM_USER+30
#define MPR_HTTP_KILL_MESSAGE		WM_USER+31
#define MPR_HTTP_SOCKET_MESSAGE		WM_USER+32
#define MPR_HTTP_TRAY_ID			0x100
#define MPR_HTTP_ICON				"appWeb.ico"

#if BLD_FEATURE_RUN_AS_SERVICE
static MprWinService	*wp;				// Global Windows Service object
#endif

////////////////////////////// Forward Declarations ////////////////////////////

static int		doServiceCommands(Mpr *mp, int serviceOp);
static void		eventLoop();
static void		closeTrayIcon();
static int		copyFile(char *from, char *to);
static int		copyTemplate(char *path, char *serverRoot, char *confFile);
static int 		getBrowserPath(char **path, int max);
static int		findInstance();
static int		initWindow();
static int		killApp(void);
static void 	mapPathDelim(char *s);
static void		memoryFailure(int askSize, int totalHeapMem, int limit);
static long		msgProc(HWND hwnd, uint msg, uint wp, long lp);
static int		openTrayIcon();
static void		printVersion();
static void		printUsage(char *program);
static int		realMain(HINSTANCE inst, MprCmdLine *cmdLine);
static void 	runBrowser(char *page);
static int		securityChecks(char *program);
static int		trayEvent(HWND hwnd, WPARAM wp, LPARAM lp);
static void		trayIconProc(void *arg, MprTimer *tp);

#if BLD_FEATURE_RUN_AS_SERVICE
static void		svcThread(void *data);
static void WINAPI 
				svcMainEntry(ulong argc, char **argv);
#endif

//////////////////////////////////// Code //////////////////////////////////////

int APIENTRY WinMain(HINSTANCE inst, HINSTANCE junk, char *args, int junk2)
{
#if BLD_FEATURE_RUN_AS_SERVICE
	MprWinService	winService(MPR_HTTP_SERVICE_NAME);

	appInst = inst;
	wp = &winService;

	//
	//	Only talk to the windows service dispatcher if running as a daemon
	//	This will block if we are a service and are being started by the
	//	service control manager. While blocked, the svcMain will be called
	//	which becomes the effective main program.
	//
	if (strstr(args, "-d") == 0 ||
			winService.startDispatcher(svcMainEntry) < 0) {

		MprCmdLine	cmdLine(args, cmdSpec);
		if (realMain(inst, &cmdLine) < 0) {
			return FALSE;
		}
		return TRUE;

	} else {
		//	FUTURE -- Is this the right return status?
		return FALSE;
	}

#else
	MprCmdLine	cmdLine(args, cmdSpec);

	if (realMain(inst, &cmdLine) < 0) {
		return FALSE;
	}
	return TRUE;
#endif
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_RUN_AS_SERVICE
//
//	Secondary entry point when started by the service control manager. Remember 
//	that the main program thread is blocked in the startDispatcher called from
//	winMain and in fact will it will be used on callbacks in WinService.
// 

static void WINAPI svcMainEntry(ulong argc, char **argv)
{
	MprCmdLine		*cmdLine;
	char			keyPath[80], *argBuf, *cp;
	int				threadId;

	argBuf = 0;
	mprSprintf(keyPath, sizeof(keyPath),
		"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", 
		MPR_HTTP_SERVICE_NAME);
	mprReadRegistry(keyPath, "ImagePath", &argBuf, MPR_MAX_STRING);

	if ((cp = strchr(argBuf, ' ')) != 0) {
		cp++;
		cmdLine = new MprCmdLine(cp, cmdSpec);
	} else {
		cmdLine = new MprCmdLine(argBuf, cmdSpec);
	}

	serviceWaitEvent = CreateEvent(0, TRUE, FALSE, 0);
	threadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) svcThread, 
		(void*) cmdLine, 0, (ulong*) &threadId);
	if (threadHandle == 0) {
		//	Should never happen, but try to keep going anyway
		realMain(0, cmdLine);
	}
	WaitForSingleObject(serviceWaitEvent, INFINITE);
	CloseHandle(serviceWaitEvent);

	delete cmdLine;
	mprFree(argBuf);
}

////////////////////////////////////////////////////////////////////////////////

static void svcThread(void *data)
{
	MprCmdLine	*cmdLine;
	int			rc;

	cmdLine = (MprCmdLine*) data;

	if (wp->registerService(threadHandle, serviceWaitEvent) < 0) {
		//	Should never happen, but try to keep going anyway
		rc = realMain(0, cmdLine);
		ExitThread(rc);
		return;
	}
	//
	//	Call the real main
	//
	isService++;
	wp->updateStatus(SERVICE_RUNNING, 0);
	rc = realMain(0, cmdLine);
	wp->updateStatus(SERVICE_STOPPED, rc);
	ExitThread(rc);
}

#endif // BLD_FEATURE_RUN_AS_SERVICE
////////////////////////////////////////////////////////////////////////////////
//
//	For service and command users alike, this is the real main
//

static int realMain(HINSTANCE inst, MprCmdLine *cmdLine)
{
	MaHttp			*http;
	char			programBuf[MPR_MAX_FNAME], dir[MPR_MAX_FNAME];
	char			parent[MPR_MAX_FNAME];
	char			*program, *argp, *logSpec, *serviceCmdLine;
	char			*confFile, *path;
	bool			outputConfig;
	int				c, errflg, kill, timeStamps, poolThreads;
	int				outputVersion;
#if BLD_FEATURE_LOG
	MprLogToFile	*logger;
	MprLogToWindow	*dialog;
#endif

	mprSetMemHandler(memoryFailure);
	mprCreateMemHeap(0, 16 * 1024, MAXINT);
	program = mprGetBaseName(cmdLine->getArgv()[0]);

	poolThreads = -1;
	timeStamps = kill = errflg = 0;
	logSpec = 0;
	confFile = "appWeb.conf";
	serviceCmdLine = 0;
	outputVersion = 0;
	outputConfig = 0;

	//
	//	By default, the binaries run in a bin directory. So we want the 
	//	serverRoot to be the parent directory. OPT.
	//
	GetModuleFileName(0, programBuf, sizeof(programBuf) - 1);
	mprGetDirName(dir, sizeof(dir), programBuf);
	mapPathDelim(dir);
	mprGetDirName(parent, sizeof(parent), dir);
	serverRoot = mprStrdup(parent);

	while ((c = cmdLine->next(&argp)) != EOF) {
		switch(c) {
		case 'c':
			outputConfig = 1;
			break;

		case 'd':
			//	No effect on windows
			break;

		case 'D':
			mprSetDebugMode(1);
			break;

		case 'f':
			confFile = argp;
			break;

		case 'k':
			kill++;
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
			serverRoot = mprStrdup(argp);
			break;
		
		case 'T':
			timeStamps++;
			break;

		case 'V':
			outputVersion++;
			break;
		
#if BLD_FEATURE_RUN_AS_SERVICE
		case 'i':
			serviceOp = MPR_INSTALL_SERVICE;
			if (strcmp(argp, "none") == 0) {
				serviceCmdLine = "";
			} else {
				serviceCmdLine = argp;
			}
			break;

		case 'g':
			serviceOp = MPR_GO_SERVICE;
			break;

		case 's':
			serviceOp = MPR_STOP_SERVICE;
			break;

		case 'u':
			serviceOp = MPR_UNINSTALL_SERVICE;
			break;

#endif
		default:
			errflg++;
			break;
		}
	}

	//
	//	FUTURE -- probably should hook the error output and graphically
	//	display
	//
	if (errflg) {
		MessageBoxEx(NULL, "Bad command line arguments", 
			MPR_HTTP_SERVICE_DISPLAY, MB_OK, 0);
		printUsage(program);
		return FALSE;
	}	

	chdir(serverRoot);
	mp = new Mpr(program);
	mp->setAppName(MPR_HTTP_SERVICE_NAME);
	mp->setAppTitle(MPR_HTTP_SERVICE_DISPLAY);
	mp->setHeadless((isService) ? 1 : 0);

	if (kill) {
		killApp();
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
	dialog = new MprLogToWindow();
	mp->addListener(logger);
	mp->addListener(dialog);
	if (timeStamps) {
		logger->enableTimeStamps(1);
	}

	if (logSpec && mp->setLogSpec(logSpec) < 0) {
		//	FUTURE -- should do more
		exit(2);
	}
#endif

	if (securityChecks(cmdLine->getArgv()[0]) < 0) {
		exit(3);
	}

#if BLD_FEATURE_RUN_AS_SERVICE
	if (serviceOp) {
		wp = new MprWinService(MPR_HTTP_SERVICE_NAME);
		switch (serviceOp) {
		case MPR_INSTALL_SERVICE:
			char path[MPR_MAX_FNAME], cmd[MPR_MAX_FNAME];
			GetModuleFileName(0, path, sizeof(path));
			mprSprintf(cmd, sizeof(cmd), "\"%s\" %s", path, serviceCmdLine);
			wp->install(MPR_HTTP_SERVICE_DISPLAY, cmd);
			break;

		case MPR_UNINSTALL_SERVICE:
			wp->remove(1);
			break;

		case MPR_GO_SERVICE:
			wp->start();
			//
			//	Give time for service to actually start 
			//
			mprSleep(2000);
			break;

		case MPR_STOP_SERVICE:
			wp->remove(0);
			break;
		}
		delete wp;
		return 0;
	}
	if (isService) {
		mprGetMpr()->setService(1);
	}
#endif

	if (serviceOp == 0 && findInstance()) {
		mprError(MPR_L, MPR_LOG, "Application %s is already active.", program);
		delete mp;
		return MPR_ERR_BUSY;
	}

	//
	//	Create the window
	// 
	if (initWindow() < 0) {
		mprError(MPR_L, MPR_ERROR, "Can't initialize application Window");
		delete mp;
		return MPR_ERR_CANT_INITIALIZE;
	}

	if (trayIcon > 0) {
		if (openTrayIcon() < 0 && mp->isService()) {
			trayTimer = new MprTimer(10 * 1000, trayIconProc, (void *) NULL);
		}
	}

	//
	//	Use windows async select and message dispatcher rather than select()
	//	FUTURE -- make this the default
	//
	mp->setAsyncSelectMode(MPR_ASYNC_SELECT);

	//
	//	Start the Timer, Socket and Pool services
	//
	if (mp->start() < 0) {
		mprError(MPR_L, MPR_USER, "Can't start MPR for %s", mp->getAppTitle());
		delete mp;
		return MPR_ERR_CANT_INITIALIZE;
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

	mprAllocSprintf(&path, MPR_MAX_FNAME, "%s/%s", serverRoot, confFile);
	if (access(path, R_OK) < 0) {
		if (copyTemplate(path, serverRoot, confFile) < 0) {
			mprError(MPR_L, MPR_USER, "Can't access config file %s", path);
			exit(5);
		}
	}
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
#if BLD_FEATURE_MULTITHREAD
			mprLog(MPR_CONFIG, "HTTP services are ready with %d pool threads\n",
				limits->maxThreads);
#else
			mprLog(MPR_CONFIG, "HTTP services are ready (single-threaded).\n");
#endif
			mp->setHeadless(1);
			eventLoop();
			http->stop();
		}
	}

	if (trayIcon > 0) {
		closeTrayIcon();
	}
	if (trayTimer) {
		trayTimer->stop(MPR_TIMEOUT_STOP);
		trayTimer->dispose();
		trayTimer = 0;
	}

	mprFree(serverRoot);

	mp->stop(0);
	delete server;
	delete http;

	delete mp;
#if BLD_FEATURE_LOG
	if (logger) {
		delete logger;
	}
	if (dialog) {
		delete dialog;
	}
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Sample main event loop. This demonstrates how to integrate Mpr with your
//	applications event loop using select()
//

void eventLoop()
{
	MSG		msg;
	int		till;

	//
	//	If single threaded or if you desire control over the event loop, you
	//	should code an event loop similar to that below:
	//
	while (!mp->isExiting()) {

		if (mp->runTimers() > 0) {
			till = 0;
		} else {
			till = mp->getIdleTime();
		}

		//
		//	This will run tasks if poolThreads == 0 (single threaded). If 
		//	multithreaded, the thread pool will run tasks
		//
		if (mp->runTasks() > 0) {			// Returns > 0 if more work to do
			till = 0;						// So don't block in select
		}
		SetTimer(appHwnd, 0, till, NULL);

		//
		//	Socket events will be serviced in the msgProc
		//
		if (GetMessage(&msg, NULL, 0, 0) == 0) {
			//	WM_QUIT received
			break;
		}
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	See if an instance of this product is already running
//

static int findInstance()
{
	HWND	hwnd;

	hwnd = FindWindow(mp->getAppName(), mp->getAppTitle());
	if (hwnd) {
		otherHwnd = hwnd;
		if (IsIconic(hwnd)) {
			ShowWindow(hwnd, SW_RESTORE);
		}
		SetForegroundWindow(hwnd);
		// SendMessage(hwnd, WM_COMMAND, MPR_MENU_HOME, 0);
		return 1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Initialize the applications's window
// 

static int initWindow()
{
	WNDCLASS 	wc;
	int			rc;

	wc.style			= CS_HREDRAW | CS_VREDRAW;
	wc.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wc.hCursor			= LoadCursor(NULL, IDC_ARROW);
	wc.cbClsExtra		= 0;
	wc.cbWndExtra		= 0;
	wc.hInstance		= (HINSTANCE) appInst;
	wc.hIcon			= NULL;
	wc.lpfnWndProc		= (WNDPROC) msgProc;
	wc.lpszMenuName		= wc.lpszClassName = mp->getAppName();

	rc = RegisterClass(&wc);
	if (rc == 0) {
		mprError(MPR_L, MPR_ERROR, "Can't register windows class");
		return -1;
	}

	appHwnd = CreateWindow(mp->getAppName(), mp->getAppTitle(), WS_OVERLAPPED,
		CW_USEDEFAULT, 0, 0, 0, NULL, NULL, appInst, NULL);

	if (! appHwnd) {
		mprError(MPR_L, MPR_ERROR, "Can't create window");
		return -1;
	}
	mp->setHwnd(appHwnd);
	mp->setSocketHwnd(appHwnd);
	mp->setSocketMessage(MPR_HTTP_SOCKET_MESSAGE);

	if (taskBarIcon > 0) {
		ShowWindow(appHwnd, SW_MINIMIZE);
		UpdateWindow(appHwnd);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Windows message processing loop
//

static long msgProc(HWND hwnd, uint msg, uint wp, long lp)
{
	char	buf[MPR_MAX_FNAME];
	int		sock, winMask;

	switch (msg) {
	case WM_DESTROY:
	case WM_QUIT:
		mp->terminate(1);
		break;
	
	case MPR_HTTP_SOCKET_MESSAGE:
		sock = wp;
		winMask = LOWORD(lp);
		// errCode = HIWORD(lp);
		mp->serviceIO(sock, winMask);
		break;

	case MPR_HTTP_TRAY_MESSAGE:
		return trayEvent(hwnd, wp, lp);
		break;

	case WM_COMMAND:
		switch (LOWORD(wp)) {
		case MPR_HTTP_MENU_CONSOLE:
			runBrowser("/admin/index.html");
			break;

		case MPR_HTTP_MENU_HELP:
			runBrowser("/doc/index.html");
			break;

		case MPR_HTTP_MENU_ABOUT:
			//
			//	Single-threaded users beware. This blocks !!!
			//
			mprSprintf(buf, sizeof(buf), "Mbedthis %s %s-%s", BLD_NAME, 
				BLD_VERSION, BLD_NUMBER);
			MessageBoxEx(NULL, buf, mp->getAppTitle(), MB_OK, 0);
			break;

		case MPR_HTTP_MENU_STOP:
			mp->terminate(1);
			break;

		default:
			return DefWindowProc(hwnd, msg, wp, lp);
		}
		break;

	default:
		return DefWindowProc(hwnd, msg, wp, lp);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Redisplay the icon. If running as a service, the icon should be retried
//	incase the user logs in.
// 

static void trayIconProc(void *arg, MprTimer *tp)
{
	closeTrayIcon();
	if (openTrayIcon() < 0) {
		tp->reschedule();
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Can be called multiple times 
//

static int openTrayIcon()
{
	NOTIFYICONDATA	data;
	HICON			iconHandle;
	static int		doOnce = 0;


	if (trayMenu == NULL) {
		trayMenu = LoadMenu(appInst, "trayMenu");
		if (! trayMenu) {
			mprError(MPR_L, MPR_LOG, "Can't locate trayMenu");
			return MPR_ERR_CANT_OPEN;
		}
	}
	if (subMenu == NULL) {
		subMenu = GetSubMenu(trayMenu, 0);
	}

	iconHandle = (HICON) LoadImage(appInst, MPR_HTTP_ICON, IMAGE_ICON, 0, 0,
		LR_LOADFROMFILE | LR_DEFAULTSIZE);
	if (iconHandle == 0) {
		mprError(MPR_L, MPR_LOG, "Can't load icon %s", MPR_HTTP_ICON);
		return MPR_ERR_CANT_INITIALIZE;
	}

	data.uID = MPR_HTTP_TRAY_ID;
	data.hWnd = appHwnd;
	data.hIcon = iconHandle;
	data.cbSize = sizeof(NOTIFYICONDATA);
	data.uCallbackMessage = MPR_HTTP_TRAY_MESSAGE;
	data.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;

	mprStrcpy(data.szTip, sizeof(data.szTip), mp->getAppTitle());

	Shell_NotifyIcon(NIM_ADD, &data);

	if (iconHandle) {
		DestroyIcon(iconHandle);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Can be caleld multiple times
//

static void closeTrayIcon()
{
	NOTIFYICONDATA	data;

	data.uID = MPR_HTTP_TRAY_ID;
	data.hWnd = appHwnd;
	data.cbSize = sizeof(NOTIFYICONDATA);
	Shell_NotifyIcon(NIM_DELETE, &data);
	if (trayMenu) {
		DestroyMenu(trayMenu);
		trayMenu = NULL;
	}
	if (subMenu) {
		DestroyMenu(subMenu);
		subMenu = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Respond to tray icon events
//

static int trayEvent(HWND hwnd, WPARAM wp, LPARAM lp)
{
	RECT		windowRect;
	POINT		p, pos;
	uint		msg;

	msg = (uint) lp;

	//
	//	Show the menu on single right click
	//
	if (msg == WM_RBUTTONUP) {
		HWND	h = GetDesktopWindow();
		GetWindowRect(h, &windowRect);
		GetCursorPos(&pos);

		p.x = pos.x;
		p.y = windowRect.bottom;

		SetForegroundWindow(appHwnd);
		TrackPopupMenu(subMenu, TPM_RIGHTALIGN | TPM_RIGHTBUTTON, p.x, p.y, 
			0, appHwnd, NULL);
		// FUTURE -- PostMessage(appHwnd, WM_NULL, 0, 0);
		mp->selectService->awaken();
		return 0;
	}

	//
	//	Launch the browser on a double click
	//
	if (msg == WM_LBUTTONDBLCLK) {
		runBrowser("/");
		return 0;
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
//
//	Send the KILL message to the MR.
// 

static int killApp(void)
{
	HWND	hwnd;
	int		running, i;

	hwnd = FindWindow(mp->getAppName(), mp->getAppTitle());
	if (hwnd) {
		running = findInstance();
		PostMessage(hwnd, WM_QUIT, 0, 0L);

		//
		//	Wait for up to ten seconds while winAppWeb exits
		//
		for (i = 0; running && i < 100; i++) {
			mprSleep(100);
			running = findInstance();
		}

	} else {
		mprError(MPR_L, MPR_USER, "Can't find %s to kill", mp->getAppName());
	}
	return 1;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Start the user's default browser
//

static void runBrowser(char *page)
{
	MprCmd		*cmd;
	char		cmdBuf[MPR_MAX_STRING];
	char		*path, *ipAddr;
	char		*pathArg;

	getBrowserPath(&path, MPR_MAX_STRING);

	ipAddr = server->getDefaultHost()->getName();
	pathArg = strstr(path, "\"%1\"");
	if (*page == '/') {
		page++;
	}

	if (pathArg == 0) {
		mprSprintf(cmdBuf, MPR_MAX_STRING, "%s http://%s/%s", path, 
			ipAddr, page);
	} else {
		//
		//	Patch out the "%1"
		//
		*pathArg = '\0';
		mprSprintf(cmdBuf, MPR_MAX_STRING, "%s \"http://%s/%s\"", path, 
			ipAddr, page);
	}
	mprLog(MPR_CONFIG, "Browser path: %s\n", cmdBuf);

	mprLog(4, "Running %s\n", cmdBuf);
	cmd = new MprCmd();
	cmd->start(cmdBuf, MPR_CMD_SHOW);
	mprFree(path);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the path to run the user's default browser. Caller must free the 
//	return string.
// 

static int getBrowserPath(char **path, int max)
{
	char	cmd[MPR_MAX_STRING];
	char	*type;
	char	*cp;

	mprAssert(path);

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
	mprLog(4, "Browser path: %s\n", *path);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////////////////////////////
//
//	Security checks. Make sure we are staring with a safe environment
//

static int securityChecks(char *program)
{
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
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Print the version information
//

static void printVersion()
{
	char	msg[80];

	mprSprintf(msg, sizeof(msg), "%s: Version: %s\n", mp->getAppName(), 
		BLD_VERSION);
	MessageBoxEx(NULL, msg, mp->getAppTitle(), MB_OK, 0);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Display the usage
//

static void printUsage(char *program)
{
	mprFprintf(MPR_STDERR, "usage: %s [-cDkmTV] [-f configFile] [-l logSpec] "
		"[-r serverRootDir]\n\n",  program);
	mprFprintf(MPR_STDERR, "Options:\n");
	mprFprintf(MPR_STDERR, "    -f configFile  Alternate to appWeb.conf\n");
	mprFprintf(MPR_STDERR, "    -c             Output the configuration\n");
	mprFprintf(MPR_STDERR, "    -D             Debug mode. Disable timeouts\n");
	mprFprintf(MPR_STDERR, "    -k             Kill existing running http\n");
	mprFprintf(MPR_STDERR, "    -m             Memory leak stats (debug)\n");
	mprFprintf(MPR_STDERR, "    -r serverRoot  Alternate Home directory\n");
	mprFprintf(MPR_STDERR, "    -T             Output log timestamps\n");
	mprFprintf(MPR_STDERR, "    -V             Output version information\n");
}

////////////////////////////////////////////////////////////////////////////////
//
//	Emergency memory failure handler. FUTURE -- add reboot code here
//	Need a -C rebootCount switch. Must set all this up first thing on booting
//	as we won't be able to get ram here.
//

static void memoryFailure(int askSize, int totalHeapMem, int limit)
{
	char	buf[MPR_MAX_STRING];

	mprSprintf(buf, sizeof(buf), "Can't get %d bytes of memory\n"
		"Total heap is %d. Limit set to %d\n", askSize, totalHeapMem, limit);
	MessageBoxEx(NULL, buf, mp->getAppTitle(), MB_OK, 0);
	exit(2);
}

////////////////////////////////////////////////////////////////////////////////

static void mapPathDelim(char *s)
{
	while (*s) {
		if (*s == '\\') {
			*s = '/';
		}
		s++;
	}
}

////////////////////////////////////////////////////////////////////////////////
#endif // WIN

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
