///
///	@file 	authHandler.h
/// @brief 	Header for authHandler
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
#ifndef _h_AUTH_MODULE
#define _h_AUTH_MODULE 1

#include	"http.h"

/////////////////////////////// Forward Definitions ////////////////////////////

class MaAuthHandler;
class MaAuthHandlerService;
class MaAuthModule;

extern "C" {
	extern int mprAuthInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// AuthModule //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaAuthModule : public MaModule {
  private:
	MaAuthHandlerService 
					*authHandlerService;
  public:
					MaAuthModule(void *handle);
					~MaAuthModule();
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MaAuthHandler /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaAuthHandlerService : public MaHandlerService {
  private:
	MprLogModule	*log;
  public:
					MaAuthHandlerService();
					~MaAuthHandlerService();
	MaHandler		*newHandler(MaServer *server, MaHost *host, char *ext);
};


class MaAuthHandler : public MaHandler {
  private:
	int				flags;
	MprStr			basicPassword;
	MprLogModule	*log;
	MprStr			userName;
#if BLD_FEATURE_DIGEST
	MprStr			cnonce;
	MprStr			nc;
	MprStr			nonce;
	MprStr			opaque;
	MprStr			qop;
	MprStr			realm;
	MprStr			responseDigest;
	MprStr			uri;
#endif
  public:
					MaAuthHandler(MprLogModule *log);
					~MaAuthHandler();
	MaHandler		*cloneHandler();
	int				decodeDigestDetails(MaRequest *rq, char *authDetails);
	void			formatAuthResponse(MaRequest *rq, MaAuth *auth, 
						int code, char *userMsg, char *logMsg);
	bool			isPasswordValid(MaRequest *rq);
	int				matchRequest(MaRequest *rq, char *uri, int uriLen);
	int				parseConfig(char *key, char *value, MaServer *server, 
						MaHost *host, MaAuth *auth, MaDir* dir, 
						MaLocation *location);
	int				run(MaRequest *rq);
	int				writeHeaders(MaRequest *rq);

	//
	//	User API
	//

	///	@synopsis Read the group authorization file.
	///	@overview Read the group authorization file replacing any existing
	///		group authorization contents.
	///	@param server Pointer to the specified server object.
	///	@param auth Pointer to the auth object (Directory or Location) for
	///		which the group file will be applied.
	///	@param path File name to read from.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				readGroupFile(MaServer *server, MaAuth *auth, char *path);

	///	@synopsis Read the user authorization file.
	///	@overview Read the user authorization file replacing any existing
	///		group authorization contents.
	///	@param server Pointer to the specified server object.
	///	@param auth Pointer to the auth object (Directory or Location) for
	///		which the user file will be applied.
	///	@param path File name to read from.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				readUserFile(MaServer *server, MaAuth *auth, char *path);

	///	@synopsis Write the group authorization file.
	///	@overview Write the current group authorization configuration to the
	///		nominated file. 
	///	@param server Pointer to the specified server object.
	///	@param auth Pointer to the auth object (Directory or Location) from
	///		which the current authorization details will be obtained.
	///	@param path File name to write to.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				writeGroupFile(MaServer *server, MaAuth *auth, char *path);

	///	@synopsis Write the user authorization file.
	///	@overview Write the current user authorization configuration to the
	///		nominated file. 
	///	@param server Pointer to the specified server object.
	///	@param auth Pointer to the auth object (Directory or Location) from
	///		which the current authorization details will be obtained.
	///	@param path File name to write to.
	///	@return Returns zero if successful, otherwise a negative MPR error code.
	int				writeUserFile(MaServer *server, MaAuth *auth, char *path);
};

////////////////////////////////////////////////////////////////////////////////
#endif // _h_AUTH_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
