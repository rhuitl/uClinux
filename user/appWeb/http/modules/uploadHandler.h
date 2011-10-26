///
///	@file	uploadHandler.h
///	@brief	Header for the uploadHandler
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	The latest version of this code is available at http://www.mbedthis.com
//
//	This module was developed on behalf of Guntermann & Drunck GmbH
//	Systementwicklung, Germany
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
#ifndef _h_UPLOAD_HANDLER
#define _h_UPLOAD_HANDLER 1

#include	"http.h"

/////////////////////////////// Forward Definitions ////////////////////////////

class MaUploadHandler;
class MaUploadHandlerService;

extern "C" {
	extern int mprUploadInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// MaUploadModule ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaUploadModule:public MaModule {
  private:
  public:
					MaUploadModule(void *handle);
					~MaUploadModule();
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// MaUploadHandlerService ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaUploadHandlerService:public MaHandlerService {
  private:
	MprList 		handlerHeaders;	 // List of handler headers
	MprLogModule 	*log;

#if BLD_FEATURE_MULTITHREAD
	MprMutex 		*mutex;
#endif

  public:
					MaUploadHandlerService();
					~MaUploadHandlerService();
	MaHandler 		*newHandler(MaServer * server, MaHost * host, char *ex);

#if BLD_FEATURE_MULTITHREAD
	inline void 	lock() { mutex->lock(); };
	inline void 	unlock() { mutex->unlock(); };
#else
	inline void 	lock() {};
	inline void 	unlock() {};
#endif
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// UploadHandler ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	A master instance of the UploadHandler is create for each referencing host.
//	A request instance is cloned from this for each request.
//

#define UPLOAD_BUF_SIZE		 4096	// Post data buffer size

//
//	contentState
//
#define MPR_UPLOAD_REQUEST_HEADER	1		// Request header
#define MPR_UPLOAD_CONTENT_HEADER	2		// content part header
#define MPR_UPLOAD_CONTENT_DATA		3		// content part binary data
#define MPR_UPLOAD_CONTENT_DATA_END	4		// end of content part data
#define MPR_UPLOAD_CONTENT_END		0x40	// End of Content

class MaUploadHandler:public MaHandler {
  private:
	MprLogModule 	*log;		 		// Pointer to the service log
	MprHashTable 	*lenv;		 		// Content part local variables
	char 			*uploadDir;			// Upload dir; relative to DOCUMENT_ROOT
	char 			*filename;			// File name from request
	char 			*filepath;			// Full incoming filename
	MprFile 		*upfile;			// Incoming file object
	char 			*boundary;			// Boundary signature
	MprBuf 			*postBuf;			// POST data buffer
	int 			contentState;

  public:
					MaUploadHandler(char *ext, MprLogModule * log);
					~MaUploadHandler();
	MaHandler 		*cloneHandler();
	int 			parseConfig(char *key, char *value, MaServer * server, 
						MaHost * host, MaAuth * auth, MaDir * dir, 
						MaLocation * location);
	void 			postData(MaRequest * rq, char *buf, int buflen);
	int 			run(MaRequest * rq);
	int 			setup(MaRequest * rq);

	int 			addParameters(char *str, MprHashTable * tab = 0);
	char 			*getHostName();
	char 			*getParameter(char *key);
	char 			*makeFilePath(MaRequest * rq, char *filename);
};

////////////////////////////////////////////////////////////////////////////////
#endif // _h_UPLOAD__HANDLER

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
