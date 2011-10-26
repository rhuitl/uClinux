///
///	@file 	appWeb.h
/// @brief 	Primary header for the Mbedthis AppWeb Library
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
#ifndef _h_APP_WEB
#define _h_APP_WEB 1

#ifndef  	__cplusplus
#include	"capi.h"
#if BLD_FEATURE_COMPAT_MODULE
#include	"compatApi.h"
#endif
#else

#include	"mpr.h"
#include	"http.h"
#include	"client.h"

//
//	FUTURE -- remove from here. Menu definitions.
//
#if WIN
#define MPR_HTTP_MENU_ABOUT		1
#define MPR_HTTP_MENU_STOP		2
#define MPR_HTTP_MENU_HELP		3
#define MPR_HTTP_MENU_CONSOLE	4
#endif

#if BLD_FEATURE_ADMIN_MODULE
#include	"adminHandler.h"
#endif
#if BLD_FEATURE_AUTH_MODULE
#include	"authHandler.h"
#endif
#if BLD_FEATURE_COPY_MODULE
#include	"copyHandler.h"
#endif
#if BLD_FEATURE_CGI_MODULE
#include	"cgiHandler.h"
#endif
#if BLD_FEATURE_EGI_MODULE
#include	"egiHandler.h"
#endif
#if BLD_FEATURE_EJS_MODULE
#include	"ejsModule.h"
#endif
#if BLD_FEATURE_ESP_MODULE
#include	"espHandler.h"
#endif
#if BLD_FEATURE_SSL_MODULE
#include	"sslModule.h"
#endif
#if BLD_FEATURE_UPLOAD_MODULE
#include	"uploadHandler.h"
#endif
#if BLD_FEATURE_COMPAT_MODULE
#include	"compatModule.h"
#endif

//
//	Internal use only.
//
void maLoadStaticModules();

#endif // __cplusplus

#endif // _h_HTTP 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
