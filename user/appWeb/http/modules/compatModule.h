///
///	@file 	compatModule.h
/// @brief 	Header for the GoAhead Compatibility module (compat.cpp)
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
#ifndef _h_COMPAT_MODULE
#define _h_COMPAT_MODULE 1

#define	UNSAFE_FUNCTIONS_OK 1

#include	"http.h"
#include	"ejs.h"
#include	"egiHandler.h"
#include	"espHandler.h"
#include	"compatApi.h"

/////////////////////////////// Extern Definitions /////////////////////////////
#if BLD_FEATURE_COMPAT_MODULE

class MaCompatModule;

extern "C" {
	extern int mprCompatInit(void *handle);
};

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// CompatModule /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class MaCompatModule : public MaModule {
  private:
  public:
					MaCompatModule(void *handle);
					~MaCompatModule();
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// WebsForm //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class WebsForm : public MaEgiForm {
  private:
	WebsFormCb		goFormCallback;

  public:
					WebsForm(char *formName, WebsFormCb fn);
					~WebsForm();
	void			run(MaRequest *rq, char *script, char *path, 
						char *query, char *postData, int postLen);
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// WebsAsp ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

class WebsAsp : public MaEspProc {
  private:
	WebsAspCb		aspCallback;
  public:
					WebsAsp(char *name, WebsAspCb fn);
					~WebsAsp();
	int				run(MaRequest *rq, int argc, char **argv);
};

////////////////////////////////////////////////////////////////////////////////
#endif // BLD_FEATURE_COMPAT_MODULE
#endif // _h_COMPAT_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
