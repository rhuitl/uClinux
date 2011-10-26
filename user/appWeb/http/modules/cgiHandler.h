///
///	@file 	cgiHandler.h
/// @brief 	Header for cgiHandler
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
#ifndef _h_CGI_MODULE
#define _h_CGI_MODULE 1

#include	"http.h"

/////////////////////////////// Forward Definitions ////////////////////////////

#if BLD_FEATURE_CGI_MODULE
class	MaCgiModule;
class	MaCgiHandler;
class	MaCgiHandlerService;

extern "C" {
	extern int mprCgiInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// CgiModule //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaCgiModule : public MaModule {
  private:
	MaCgiHandlerService	
					*cgiHandlerService;
  public:
					MaCgiModule(void *handle);
					~MaCgiModule();
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// CgiHandler /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaCgiHandlerService : public MaHandlerService {
  private:
	MprLogModule	*log;
	MaCgiHandler	*cgiHandler;

  public:
					MaCgiHandlerService();
					~MaCgiHandlerService();
	MaHandler		*newHandler(MaServer *server, MaHost *host, char *ex);
};

//
//	cgiFlags
//
#define MPR_CGI_NON_PARSED_HEADER	0x1		// CGI program creates HTTP headers
#define MPR_CGI_HEADER_SEEN			0x2		// Server has parsed CGI response

class MaCgiHandler : public MaHandler {
  private:
	MprBuf			*headerBuf;
	int				cgiFlags;
	MprCmd			*cmd;
	MprLogModule	*log;
	MprStr			newLocation;

  public:
					MaCgiHandler(char *ext, MprLogModule *log);
					~MaCgiHandler();
	void			buildArgs(int *argcp, char ***argvp, MprCmd *cmd, 
						MaRequest *rq, char *query);
	int				cgiDone(MaRequest *rq, int exitCode);
	MaHandler		*cloneHandler();
	void			parseHeader(MaRequest *rq);
	void			postData(MaRequest *rq, char *buf, int buflen);
	void			outputData(MaRequest *rq);
	int				parseConfig(char *key, char *value, MaServer *server, 
						MaHost *host, MaAuth *auth, MaDir* dir, 
						MaLocation *location);
	int				run(MaRequest *rq);
	int				setup(MaRequest *rq);
#if WIN
	void			findExecutable(char **program, char **script, 
						char **bangScript, MaRequest *rq, char *fileName);
#endif
};

#endif // BLD_FEATURE_CGI_MODULE
////////////////////////////////////////////////////////////////////////////////
#endif // _h_CGI_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
