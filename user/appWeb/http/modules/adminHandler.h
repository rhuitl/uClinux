///
///	@file 	adminHandler.h
/// @brief 	Header for the adminHandler
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
#ifndef _h_ADMIN_MODULE
#define _h_ADMIN_MODULE 1

#include	"http.h"

/////////////////////////////// Forward Definitions ////////////////////////////

#if BLD_FEATURE_ADMIN_MODULE
class MaAdminModule;
class MaAdminHandler;
class MaAdminHandlerService;

extern "C" {
	extern int mprAdminInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaAdminModule ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaAdminModule : public MaModule {
  private:
	MaAdminHandlerService 	
					*adminHandlerService;
  public:
					MaAdminModule(void *handle);
					~MaAdminModule();
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// MaAdminHandlerService ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaAdminHandlerService : public MaHandlerService {
  public:
					MaAdminHandlerService();
					~MaAdminHandlerService();
	MaHandler		*newHandler(MaServer *server, MaHost *host, char *ex);
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaAdminHandler ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaAdminHandler : public MaHandler {
  private:
  public:
					MaAdminHandler();
					~MaAdminHandler();
	MaHandler		*cloneHandler();
	int				run(MaRequest *rq);
};

#endif // BLD_FEATURE_ADMIN_MODULE
////////////////////////////////////////////////////////////////////////////////
#endif // _h_ADMIN_MODULE 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
