///
///	@file 	espHandler.h
/// @brief 	Header for the espHandler
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
#ifndef _h_ESP_MODULE
#define _h_ESP_MODULE 1

#include	"ejs.h"
#include	"http.h"

////////////////////////////// Forward Definitions /////////////////////////////

extern "C" {
	extern int mprEspInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// EspModule //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaEspModule : public MaModule {
  private:
  public:
					MaEspModule(void *handle);
					~MaEspModule();
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// EspProc ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

///
///	@brief Create an ESP procedure
///
///	Instances of the MaEspProc class are created for each ESP procedure.
///	When the ESP procedure is invoked from the web page, the \a run method
///	will be invoked. The run method should write the appropriate data to the
///	browser in response.
///
class MaEspProc : public MprEjsProc {
  private:
	char			*name;
  public:
	///
	///	@synopsis Create an ESP procedure
	///	@overview Instances of this class represent ESP procedures. 
	///		When the ESP procedure is invoked, the \a run method will be 
	///		called.
	///	@param procName Name of the ESP procedure. This is the name to use
	///		in the ESP web page.
	/// @stability Evolving.
	/// @library libappWeb
	///	@see MaEsp
					MaEspProc(char *procName);
					MaEspProc(MaServer *server, MaHost *host, char *procName);
	virtual			~MaEspProc();
	char			*getName();
	int				run(void *userHandle, int argc, char **argv);
	virtual int		run(MaRequest *rq, int argc, char **argv) = 0;
	void			setError(char *str);
	void			setErrorFmt(char *fmt, ...);
	void			setResult(char *str);
	void			setResultFmt(char *fmt, ...);
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// EspHandlerService ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaEspHandlerService : public MaHandlerService {
  private:
	MprLogModule	*log;
	MprList			handlerHeaders;			// List of handler headers
	MaEspProc**		standardProcs;
	int				nextProc;
	int				maxProc;
	MprHashTable	*procs;					// One table for all servers/hosts

#if BLD_FEATURE_MULTITHREAD
	MprMutex		*mutex;
#endif

  public:
					MaEspHandlerService();
					~MaEspHandlerService();
	int				start();
	int				startControls();
	void			insertProc(MaServer *server, MaHost *host, MaEspProc *proc);
	MaHandler		*newHandler(MaServer *server, MaHost *host, char *ex);

#if BLD_FEATURE_MULTITHREAD
	inline void		lock() { mutex->lock(); };
	inline void		unlock() { mutex->unlock(); };
#else
	inline void		lock() { };
	inline void		unlock() { };
#endif
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// EspHandler //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	A master instance of the EgiHandler is create for each referencing host.
//	A request instance is cloned from this for each request.
//
//	Esp Flags
//
#define MPR_ESP_CLONED	0x1						// Cloned handler

class MaEspHandler : public MaHandler {
  private:
	MprScriptEngine* engine;
	int				espFlags;
	MprLogModule	*log;
	MprBuf*			postBuf;
	MprHashTable	*procs;					// Pointer to service->procs

  public:
					MaEspHandler(char *ext, MprLogModule *log, 
						MprHashTable *procs);
					~MaEspHandler();
	MaHandler		*cloneHandler();
	MprBuf*			getPostBuf();
	void			insertProc(MaEspProc *proc);
	void			postData(MaRequest *rq, char *buf, int buflen);
	int				process(MaRequest *rq);
	int				buildScript(MaRequest *rq, char **buf, int *len, 
						char *input);
	int				run(MaRequest *rq);
	int				setup(MaRequest *rq);
	char			*setScriptEngine(MaRequest *rq, char *cp);
	char			*skipSpace(char *s);
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// ESP Controls /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaEspInclude : public MaEspProc {
  public:
					MaEspInclude() : MaEspProc("include") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspRedirect : public MaEspProc {
  public:
					MaEspRedirect() : MaEspProc("redirect") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspTabs : public MaEspProc {
  public:
			MaEspTabs() : MaEspProc("makeTabs") {};
	int		run(MaRequest *rq, int argc, char **argv);
};

class MaEspWrite : public MaEspProc {
  public:
					MaEspWrite() : MaEspProc("write") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

#if BLD_FEATURE_SESSION
class MaEspCreateSession : public MaEspProc {
  public:
					MaEspCreateSession() : MaEspProc("createSession") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspDestroySession : public MaEspProc {
  public:
					MaEspDestroySession() : MaEspProc("destroySession") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspGetSessionData : public MaEspProc {
  public:
					MaEspGetSessionData() : MaEspProc("getSessionData") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspGetSessionId : public MaEspProc {
  public:
					MaEspGetSessionId() : MaEspProc("getSessionId") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspSetSessionData : public MaEspProc {
  public:
					MaEspSetSessionData() : MaEspProc("setSessionData") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspTestSessionData : public MaEspProc {
  public:
					MaEspTestSessionData() : MaEspProc("testSessionData") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

class MaEspUnsetSessionData : public MaEspProc {
  public:
					MaEspUnsetSessionData() : MaEspProc("unsetSessionData") {};
	int				run(MaRequest *rq, int argc, char **argv);
};

#endif	// BLD_FEATURE_SESSION
////////////////////////////////////////////////////////////////////////////////
#endif // _h_ESP_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
