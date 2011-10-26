///
///	@file 	ejsModule.cpp
/// @brief 	Embedded JavaScript Module
///
///	Dynamically loadable embedded javascript engine for use by ESP.
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

#include	"ejsModule.h"

//////////////////////////////////// Locals ////////////////////////////////////
#if BLD_FEATURE_EJS_MODULE

static MprEjsService	*jsService;

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaEjsModule //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int mprEjsInit(void *handle)
{
	if (maGetHttp() == 0) {
		return MPR_ERR_NOT_INITIALIZED;
	}
	new MaEjsModule(handle);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaEjsModule::MaEjsModule(void *handle) : MaModule("ejs", handle)
{
	jsService = new MprEjsService();
}

////////////////////////////////////////////////////////////////////////////////

MaEjsModule::~MaEjsModule()
{
	delete jsService;
}

////////////////////////////////////////////////////////////////////////////////
#else 
void mprEjsModuleDummy() {}

#endif // BLD_FEATURE_EJS_MODULE

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
