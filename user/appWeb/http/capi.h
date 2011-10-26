///
///	@file 	capi.h
/// @brief 	C language API
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
////////////////////////////////////////////////////////////////////////////////
#ifndef _h_CAPI
#define _h_CAPI 1

#include "mpr.h"

#if BLD_FEATURE_C_API_MODULE
#ifdef  __cplusplus
extern "C" {
#endif

/////////////////////////////////// Types //////////////////////////////////////

#if IN_C_API_MODULE
	typedef void (*MaEgiCb)(MaRequest *rq, char *script, char *uri, 
		char *query, char *postData, int postLen);
	typedef int  (*MaEspCb)(MaRequest *rq, int argc, char **argv);

	extern "C" int mprCapiInit(void *handle);
	
	class MaCapiModule : public MaModule {
	  private:
	  public:
						MaCapiModule(void *handle);
						~MaCapiModule();
	};

#else
	typedef struct { void *x; } Mpr;
	typedef struct { void *x; } MaHttp;
	typedef struct { void *x; } MaServer;
	typedef struct { void *x; } MaRequest;
	typedef void (*MaEgiCb)(MaRequest *rq, char *script, char *uri, char *query,
		char *postData, int postLen);
	typedef int  (*MaEspCb)(MaRequest *rq, int argc, char **argv);
#endif

//////////////////////////////////// Code //////////////////////////////////////

///
///	@synopsis configure the entire server from a configuration file.
///	@overview Servers are configured via an Apache-style configuration file.
///		A server may listen on multiple ports and may contain multiple 
///		virtual hosts.
///	@param server Pointer to the MaServer object created via maCreateServer.
///	@param configFile Path of the configuration file.
///	@param outputConfig If TRUE, output the parsed configuration settings
///		to the standard output (console).
///	@return Returns zero if successful, otherwise a negative MPR error code.
/// @library libappWeb
///	@see maDeleteHttp
extern int		maConfigureServer(MaServer *server, char *configFile, 
				int outputConfig);

///
///	@synopsis Decode a buffer and create environment variables.
///	@overview This call will URL decode the buffer and create AppWeb 
///		environment variables for each keyword.
///	@param rq Request handle
///	@param buf Buffer to decode into environment variables. Does not need
///		to be null terminated.
///	@param len Length of buffer. 
/// @stability Evolving.
/// @library libappWeb
///	@see maDeleteHttp
extern void 	maCreateEnvVars(MaRequest *rq, char *buf, int len);

///
///	@synopsis Create the application's HTTP object
///	@overview One MaHttp object is needed per application to manage all 
///		servers.
///	@returns Pointer to the MaHttp object.
/// @stability Evolving.
/// @library libappWeb
///	@see maDeleteHttp
extern MaHttp 	*maCreateHttp();

///
///	@synopsis Create a HTTP server.
///	@overview Creates a logical HTTP server that may consist of multiple 
///		virtual servers. 
///	@param http Pointer to the MaHttp object created by maCreateHttp.
///	@param name Descriptive name to give to the server.
///	@param serverRoot Top level path of the directory containing the server.
///	@returns Pointer to the MaServer object
/// @stability Evolving.
/// @library libappWeb
///	@see 
extern MaServer	*maCreateServer(MaHttp *http, char *name, char *serverRoot);

///
///	@synopsis Defines a C lanaguage ESP procedure
///	@overview This call links a C procedure to an ESP name. When a web page
///		containing a call to the procedure, the ESP handler will ensure the
///		nominated code is called.
///	@param name Name to use in the ESP web page for this ESP procedure.
///	@param fn C callback function to invoke.
///	@returns Zero if successful. Otherwise it returns an MPR error code.
/// @stability Evolving.
/// @library libappWeb
///	@see 
extern int 		maDefineEsp(char *name, MaEspCb fn);

///
///	@synopsis Defines a C language EGI form
///	@overview This call links a C procedure to an EGI name. When a URL
///		referencing the form is invoked, the EGI handler will ensure the
///		nominated code is called. E.g. The URL: 
///
///	@code
///		http://localhost/egi/myForm?name=Julie
///	@endcode
///
///	Could be enabled by calling maDefineEgiForm("myForm", myFormProc);	
///	@param name Name to publish the form as. This appears in the URL. Names 
///		must therefore only contain valid URL characters.
///	@param fn C callback function to invoke.
///	@returns Zero if successful. Otherwise it returns an MPR error code.
/// @stability Evolving.
/// @library libappWeb
///	@see 
extern int 		maDefineEgiForm(char *name, MaEgiCb fn);

///
///	@synopsis Delete the MaHttp object
///	@overview Before exiting an application, maDeleteHttp should be called to
///		delete the MaHttp object.
///	@param http MaHttp application object returned from maCreateHttp.
/// @stability Evolving.
/// @library libappWeb
///	@see maCreateHttp, maCreateServer, maDeleteServer
extern void 	maDeleteHttp(MaHttp *http);

///
///	@synopsis Delete the MaServer object
///	@overview Before exiting an application, maDeleteServer should be called
///		to delete the maServer object.
///	@param server MaServer object returned from maCreateServer
/// @stability Evolving.
/// @library libappWeb
///	@see maCreateHttp, maCreateServer, maDeleteHttp
extern void 	maDeleteServer(MaServer *server);

///
///	@synopsis Return an error to the client (user's browser)
///	@overview If a handler encounters an error, it can call 
///		maRequestError to return the appropriate HTTP 
///		error code and message to the user's browser.
///	@param rq Request handle
///	@param code HTTP error code. E.g. 500 for an internal server error.
///	@param fmt Printf style format string followed by assocated arguments.
/// @stability Evolving.
/// @library libappWeb
///	@see maWrite
extern void 	maRequestError(MaRequest *rq, int code, char *fmt, ...);

///
///	@synopsis Return the current configuration file line number 
///	@overview If a error is encountered when parsing the configuration file,
///		maGetConfigErrorLine will return the current line number for error
///		reporting purposes.
///	@param server MaServer object returned from maCreateServer.
///	@returns The current line number (origin 1).
/// @stability Evolving.
/// @library libappWeb
///	@see maConfigureServer
extern int		maGetConfigErrorLine(MaServer *server);

#if BLD_FEATURE_COOKIE || BLD_FEATURE_SESSION
///
///	@synopsis Return the request cookie.
///	@overview A client request may optionally include a HTTP cookie. This
///		request returns a pointer to the cookie string.
///	@param rq Request object handle
///	@returns Pointer to the cookie for the current request.
/// @stability Evolving.
/// @library libappWeb
///	@see maGetFileName
extern char 	*maGetCookie(MaRequest *rq);
extern void		maGetCrackedCookie(MaRequest *rq, char **name, char **value,
					char **path);
extern void		maSetCookie(MaRequest *rq, char *name, char *value, 
					int lifetime, char *path,	bool secure);
extern void		maSetHeader(MaRequest *rq, char *value, int allowMultiple);
#endif

extern void		maSetResponseCode(MaRequest *rq, int code);

///
///	@synopsis Return the document file name to satisfy the current HTTP request.
///	@overview Certain URLs are mapped to corresponding documents in the file
///		system. These may be HTML pages, CSS files or GIF/JPEG graphic files,
///		among other file types. maGetFileName will return the local file system
///		path to the document to return to the user. If the URL does not map to 
///		a local document, for example: EGI requests are served internally 
///		and do not map onto a local file name, then this call will not 
///		return meaningful data.
///	@param rq Request object handle
///	@returns Pointer to the local file name for the document. Returns empty 
///		string if the handler does not map the URL onto a local document.
/// @stability Evolving.
/// @library libappWeb
///	@see maSetFileName
extern char 	*maGetFileName(MaRequest *rq);

///
///	@synopsis Return the value of the specified HTTP environment variable
///	@overview This call will query the value of HTTP environment variables.
///		These variables are used by CGI, EGI and ESP handlers. ESP pages
///		and EGI forms may access these variables.
///	@param rq Request object handle
///	@param var Name of the variable to access.
///	@param defaultValue Default value to return if the variable is not defined.
///	@returns The value of the variable if it is defined. Otherwise the 
///		\a defaultValue is returned.
/// @stability Evolving.
/// @library libappWeb
///	@see maSetVar
extern char 	*maGetVar(MaRequest *rq, char *var, char *defaultValue);

///
///	@synopsis Redirect the user's browser to a new location
///	@overview maRedirect will respond to the current request with a HTTP 
///		redirection (code 301). The redirection may be to another page with
///		the current web, or it may be to a different server. 
///	@param rq Request object handle
///	@param code HTTP redirection code
///	@param url URL representing the new location. May omit the 
///		"http://server/" prefix for redirections within the exiting web.
/// @stability Evolving.
/// @library libappWeb
///	@see maRequestError
extern void 	maRedirect(MaRequest *rq, int code, char *url);

///
///	@synopsis Set the local file name for the document that satisfies this 
///		request.
///	@overview This call defines the local file name for a document which will
///		be returned to the user's browser.
///	@param rq Request object handle.
///	@param fileName Path name in the local file system for the document.
///	@returns Returns zero if successful. Otherwise a negative MPR error code
///		will be returned. On errors, maSetFileName will call requestError and
///		will terminate the request.
/// @stability Evolving.
/// @library libappWeb
///	@see maGetFileName
extern int 	maSetFileName(MaRequest *rq, char *fileName);

///
///	@synopsis Set the value of a HTTP environment variable
///	@overview This call will define the value of an HTTP environment variable.
///		These variables are used by CGI, EGI and ESP handlers. ESP pages
///		and EGI forms may access these variables. The variable will be 
///		created if it does not exist. If it already exists, its value will be
///		updated.
///	@param rq Request object handle.
///	@param var Name of environment variable to set.
///	@param value Value to set.
/// @stability Evolving.
/// @library libappWeb
///	@see maGetVar
extern void 	maSetVar(MaRequest *rq, char *var, char *value);

///
///	@synopsis Activate HTTP servers.
///	@synopsis Start all the logical servers corresponding to the supplied 
///		MaHttp object. Once stared, the default server an any virtual 
///		servers will be activated and begin responding to HTTP requests.
///	@param http MaHttp object created via maCreateHttp.
///	@returns Zero if successful, otherwise a MPR error code is returned.
/// @stability Evolving.
/// @library libappWeb
///	@see maStopServers
extern int		maStartServers(MaHttp *http);

///
///	@synopsis Deactivate HTTP servers
///	@overview Stop all the logical servers corresponding to the supplied
///		MaHttp object. The servers will cease serving new requests immediately.
///		Existing requests will continue to be processed by the handlers. 
///	@param http MaHttp object created via maCreateHttp
/// @stability Evolving.
/// @library libappWeb
///	@see maStartServers
extern void	 	maStopServers(MaHttp *http);

///
///	@synopsis Write a block of data back to the user's browser.
///	@overview This call is the most efficient way to return data back to 
///		a user's browser. 
///	@param rq Request object handle
///	@param buf Pointer to the data buffer to write
///	@param size Size of the buffer in bytes
///	@returns Number of bytes written. Should equal \a size. On errors, returns
///		a negative MPR error code.
/// @stability Evolving.
/// @library libappWeb
///	@see maWriteFmt, maWriteStr
extern int 		maWrite(MaRequest *rq, char *buf, int size);

///
///	@synopsis Write a formatted string back to the user's browser.
///	@overview Format a \a printf style string and write back to the browser.
///	@param rq Request object handle.
///	@param fmt Printf style format string followed by assocated arguments.
///	@returns Number of bytes written. On errors, returns a negative MPR 
///		error code.
/// @stability Evolving.
/// @library libappWeb
///	@see  maWrite, maWriteStr
extern int 		maWriteFmt(MaRequest *rq, char* fmt, ...);

///
///	@synopsis Write a string back to the user's browser.
///	@overview Write the string back to the browser.
///	@param rq Request object handle.
///	@param s Pointer to string to write.
///	@returns Number of bytes written. On errors, returns a negative MPR 
///		error code.
/// @stability Evolving.
/// @library libappWeb
///	@see  maWrite, maWriteFmt
extern int 		maWriteStr(MaRequest *rq, char *s);

///
///	@synopsis Set the result of an ESP procedure call.
///	@overview Set the result of an ESP procedure call. This value is returned
///		from the ESP script call.
///	@param rq Request object handle.
///	@param s Pointer to string to use as the result.
/// @stability Evolving.
/// @library libappWeb
///	@see  maWrite, maWriteFmt
extern void 		maSetResult(MaRequest *rq, char *s);

///
///	@synopsis Add a log listener that logs messages to a file.
///	@overview The MPR logging service permits multiple listeners to be
///		registered to receive log messages. The LogFile listenener logs 
///		messages to the file specified by mprSetLogSpec.
/// @stability Evolving.
/// @library libappWeb
///	@see mprSetLogSpec.
extern void		mprAddLogFileListener();

///
///	@synopsis Create an MPR instance for the application.
///	@overview To support AppWeb, an application needs the services of the
///		Mbedthis Portable Runtime (MPR). This call activates the MPR and 
///		must be issued prior to any other AppWeb API call.
///	@param appName Name of the application. This is used for internal error
///		reporting from AppWeb and the MPR.
///	@returns Zero if successful. Otherwise returns a negative MPR error code.
/// @stability Evolving.
/// @library libappWeb
///	@see mprDeleteMpr
extern int		mprCreateMpr(char *appName);

///
///	@synopsis Delete the MPR object
///	@overview This call will shutdown the MPR and terminate all MPR services.
///		An application should call mprDeleteMpr before exiting.
/// @stability Evolving.
/// @library libappWeb
///	@see mprCreateMpr
extern void		mprDeleteMpr();

///
///	@synopsis Delete the MPR object
///	@overview This call will shutdown the MPR and terminate all MPR services.
///		An application should call mprDeleteMpr before exiting.
/// @stability Evolving.
/// @library libappWeb
///	@see mprCreateMpr
extern void		mprDeleteMpr();

///
/// @synopsis Return the current async select mode
///	@overview Return TRUE if the application is using windows async message
///		select rather than the Unix select mechanism.
///	@returns TRUE if using async select.
/// @stability Evolving.
/// @library libappWeb
///	@see mprSetAsyncSelectMode
extern int		mprGetAsyncSelectMode();

///
///	@synopsis Service pending I/O events
///	@overview The MPR includes a unified I/O event service which efficiently
///		processes I/O and invokes handlers for the underlying socket or
///		file descriptors (on Unix). The MPR Socket layer will automatically
///		integrate with the event mechanism so that I/O will cause the socket
///		callback handlers to be invoked. 
///
///		mprServiceEvents is the primary mechanism to wait for I/O events
///		and to cause them to be serviced. When called in multi-threaded
///		applications, it will use a thread pool to continually service 
///		events until the application is instructed to exit via mprTerminate.
///		When used in single-threaded applications, it is usually used 
///		within a larger custom event loop in the application.
///	@param loopOnce Determines if mprServiceEvents will service only the 
///		current events or if it continue to service future events.
///	@param maxTimeout If \a loopOnce is TRUE, \a maxTimeout specifies the
///		time to wait 
///		current events or if it continue to service future events.
/// @remarks Callers have several options when integrating the MPR and 
///		products using the MPR. You can:
///		@li run a dedicated thread servicing events
///		@li	call serviceEvents from your own event loop
///		@li create your own routine to service events using 
///			mprServiceEvents() as a prototype.
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, mprServiceIO
extern void		mprServiceEvents(int loopOnce, int maxTimeout);

///
/// @synopsis Set the current async select mode
///	@overview Determine if the application is using windows async message
///		select rather than the Unix select mechanism.
///	@param on If TRUE, enable async select mechanism.
/// @stability Evolving.
/// @library libappWeb
///	@see mprGetAsyncSelectMode
extern void		mprSetAsyncSelectMode(int on);

///
///	@synopsis Define the file to use for logging messages.
///	@overview This call specifies a log file specification to use with
///		the LogFile listener. The \a logSpec parameter specifies the 
///		log file name and optionally specifies :
///
///		@li Log verbosity level
///		@li Maximum log file size
///		@li List of module names to log
///
///	@param logSpec Log file specification of the format:
///	@code
///		fileName[[,moduleName]...][:level][.maxSize]
///	@endcode
///
///	Module names (if specified) are internal MPR names such as \b socket. 
///	This allows you to log trace from only designated modules. The \a level 
///	must be between 0 and 9 with 9 being the most verbose. A good normal 
///	level is 2. The \a maxSize specification is the size of the logfile in 
///	MB before rotating. When rotated, the old file will have a ".old" 
///	appended.
///	@return Returns zero if successful. Otherwise returns a negative MPR
///	error code.
/// @stability Evolving.
/// @library libappWeb
///	@see mprAddLogFileListener, mprLog, mprError
extern void	 	mprSetLogSpec(char *logSpec);

///
///	@synopsis Starts the MPR services 
///	@overview After creating the MPR object via mprCreateMpr, this call will 
///		fully initialize the MPR and to start all services. These services 
///		include thread services, the thread pool, timer services, select
///		handlers and command execution services.
///	@param startFlags Or the following flags:
///		@li	MPR_SERVICE_THREAD to create a service thread to run select.
///			The thread will call mprServiceEvents to process I/O events.
///		@li MPR_KILLABLE to create a pid file to support killing running MPRs.
///	@returns Returns zero if successful, otherwise returns a negative MPR
///		error code.
/// @stability Evolving.
/// @library libappWeb
///	@see mprCreateMpr, mprStopMpr
extern int 		mprStartMpr(int startFlags);

///
///	@synopsis Stop the MPR services
///	@overview Applications should call mprStopMpr before exiting to gracefully
///		terminate MPR processing.
/// @stability Evolving.
/// @library libappWeb
///	@see mprCreateMpr, mprStartMpr
extern void		mprStopMpr();

///
///	@synopsis Instruct the application to exit
///	@overview Calling mprTerminate will cause the MPR event loop to exit. When
///		called with the \a graceful parameter set to TRUE, mprTerminate will 
///		set the \a isExiting flag and take no further action. The MPR 
///		event loop or the applications event loop will check this flag by
///		calling mprIsExiting to determine if the application should exit.
///		If \a graceful is FALSE, mprTerminate will call \a exit for an 
///		immediate application termination.
///	@param graceful If FALSE, call exit and terminate the application 
///		immediately. If TRUE, set the MPR \a isExiting flag. 
/// @stability Evolving.
/// @library libappWeb
///	@see mprIsExiting, mprServiceEvents
extern void		mprTerminate(int graceful);

///
///	@synopsis Log a message to the MPR logging facility
///	@overview Log a message at the specified log level
///	@param level log level between 0 and 9, 9 being the most verbose level.
///	@param fmt Printf style format string. Variable number of arguments to 
///	@param ... Variable number of arguments for printf data
///	@return Returns zero if successful. Otherwise a negative MPR error code.
/// @remarks mprLog is highly useful as a debugging aid when integrating
///	or when developing new modules. 
/// @stability Evolving.
/// @library libappWeb
///	@see mprError
extern void		mprTrace(int level, char *fmt, ...);

///
///	@synopsis Get the select file masks for all MPR file and sockets.
///	@overview The getFds call set the select I/O masks for all files and
///		sockets in use by the MPR. Application event loops should call
///		getFds and then OR in their own file descriptors before calling
///		select using the masks. getFds will only modify the masks if 
///		the I/O interests of underlying file descriptors have changed.
///		This means that getFds may not modify the masks if nothing much
///		has changed. It is imperative that you not clear the masks between
///		calls to getFds. Consequently, you should copy or save the masks 
///		before using them in select -- as select will modify the masks.
///		If you want to force getFds to rebuild the masks, zero the value 
///		pointed to by the lastGet parameter.
///	@param readInterest fd_set read interest mask
///	@param writeInterest fd_set write interest mask
///	@param exceptInterest Not used
///	@param maxFd Number of the highest file descriptor plus 1. This 
///		value is used by select.
///	@param lastGet Pointer to a timestamp integer used by getFds to 
///		manage when getFds was last run. The value pointed to should be
///		initialized to -1.
///	@returns Returns TRUE if the masks were modified.
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, mprGetIdleTime, mprRunTasks, mprRunTimers, mprServiceEvents
extern int		mprGetFds(fd_set* readInterest, fd_set* writeInterest, 
						fd_set* exceptInterest, int *maxFd, int *lastGet);

///
///	@synopsis Return the time to wait till the next timer or event is due.
///	@overview Application event loops should call getIdleTime to determine
///		how long they should sleep waiting for the next event to occur.
///	@returns Returns the number of milli-seconds till the next timer is due.
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, runTimers
extern int		mprGetIdleTime();

///
///	@synopsis Determine if the application is exiting
///	@overview Returns TRUE if the application has been instructed to exit
///		via mprTerminate. The application's main event loop should 
///		call isExiting whenever an event is detected. If isExiting returns
///		TRUE, the application should gracefully exit.
///	@return Returns TRUE if the application should exit.
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr
extern int		mprIsExiting();

///
///	@synopsis Execute all runable tasks
///	@overview If an application is running single-threaded, a call to 
///		runTasks will cause all queued Tasks to run. If multi-threaded, 
///		this call will have no effect. Application event loops should call
///		runTasks before sleeping to ensure all tasks have had a chance to
//		run.
///	@returns Returns TRUE if any tasks were run.
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, mprRunTimers, mprGetIdleTime, mprServiceEvents, mprServiceIO
extern int		mprRunTasks();

///
///	@synopsis Check timers and run all due timers.
///	@overview The runTimers method should be called by event loops to
///		call any timers that are due. 
///	@returns Returns TRUE if any timers were run.
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, mprRunTasks, mprGetIdleTime, mprServiceEvents, mprServiceIO
extern int		mprRunTimers();

///
///	@synopsis Service any pending I/O events
///	@overview serviceIO will analyse the provided select masks and will
///		call all registered select handlers if an I/O event has occurred
///		for that handler. MprSocket automatically creates select handlers
///		on Unix and so the socket handlers will be also invoked if an I/O
///		event occurs. This routine call be called on Windows, but the
///		native windows message mechanism will provide higher throughput.
///	@param readyFds Number of file descriptors with I/O events
///	@param readFds Read select mask
///	@param writeFds Write select mask
///	@param exceptFds Exception select mask
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, mprGetIdleTime, mprRunTasks, mprRunTimers, mprGetFds, 
///		mprServiceEvents
extern void		mprServiceIO(int readyFds, fd_set* readFds, fd_set* writeFds, 
						fd_set* exceptFds);

///
///	@synopsis Service any pending I/O events for a given socket (Windows)
///	@overview serviceIO service the I/O event specified in \a winMask for
///		the given socket.
///	@param sock Socket descriptor
///	@param winMask Windows Message I/O mask
/// @stability Evolving.
/// @library libappWeb
///	@see Mpr, mprGetIdleTime, mprRunTasks, mprRunTimers, mprGetFds, 
///		mprServiceEvents
#if WIN
extern void		mprServiceWinIO(int sock, int winMask);
#endif

#if WIN
///
///	@synopsis Set the Window handle for the application
///	@overview Define the window handle for the application that the MPR and
///		AppWeb will use.
///	@param appHwnd Application window handle
/// @stability Evolving.
/// @library libappWeb
///	@see mprSetSocketHwnd, mprServiceIO
extern void mprSetHwnd(HWND appHwnd);

///
///	@synopsis Set the socket handle for the application
///	@overview Define the window handle to use for socket events.
///	@param socketHwnd Socket window handle
/// @stability Evolving.
/// @library libappWeb
///	@see mprSetHwnd, mprServiceIO
extern void mprSetSocketHwnd(HWND socketHwnd);

///
///	@synopsis Set the windows message type to use for socket messages
///	@overview Define the message type that the MPR will use in response to
///		socket I/O events.
///	@param msgId Windows message type.
/// @stability Evolving.
/// @library libappWeb
///	@see mprSetHwnd, mprSetSocketHwnd, mprServiceIO
extern void mprSetSocketMessage(int  msgId);
#endif

#if DMF || 1
extern char 	*maGetUserName(MaRequest *rq);
extern char 	*maGetUri(MaRequest *rq);
extern int 		maIsKeepAlive(MaRequest *rq);
extern int 		maIsEsp(MaRequest *rq);
#endif

//
//	DLL initialization modules
//
#if BLD_FEATURE_ADMIN_MODULE
extern int mprAdminInit(void *handle);
#endif
#if BLD_FEATURE_AUTH_MODULE
extern int mprAuthInit(void *handle);
#endif
#if BLD_FEATURE_CGI_MODULE
extern int mprCgiInit(void *handle);
#endif
#if BLD_FEATURE_COMPAT_MODULE
extern int mprCompatInit(void *handle);
#endif
#if BLD_FEATURE_COPY_MODULE
extern int mprCopyInit(void *handle);
#endif
#if BLD_FEATURE_EGI_MODULE
extern int mprEgiInit(void *handle);
#endif
#if BLD_FEATURE_EJS_MODULE
extern int mprEjsInit(void *handle);
#endif
#if BLD_FEATURE_ESP_MODULE
extern int mprEspInit(void *handle);
#endif
#if BLD_FEATURE_SSL_MODULE
extern int mprSslInit(void *handle);
#endif
#if BLD_FEATURE_UPLOAD_MODULE
extern int mprUploadInit(void *handle);
#endif
#if BLD_FEATURE_OPENSSL_MODULE
extern int mprOpenSslInit(void *handle);
#endif
#if BLD_FEATURE_PHP_MODULE
extern int mprPhp4Init(void *handle);
#endif

////////////////////////////////////////////////////////////////////////////////
#ifdef  __cplusplus
} 	// extern "C" 
#endif

#endif // BLD_FEATURE_C_API_MODULE
#endif // _h_CAPI 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
