///
///	@file 	appWebStaticLink.cpp
/// @brief 	Statically link code between appWeb and winAppWeb
//
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

#include	"appWeb/appWeb.h"

#if BLD_FEATURE_PHP4_MODULE_BUILTIN
#include	"http/modules/php4/php4Handler.h"
#endif
#if BLD_FEATURE_PHP5_MODULE_BUILTIN
#include	"http/modules/php5/php5Handler.h"
#endif
#if BLD_FEATURE_OPENSSL_MODULE_BUILTIN
#include	"http/modules/openSsl/openSslModule.h"
#endif

//////////////////////////////////// Code //////////////////////////////////////

void maLoadStaticModules()
{
#if BLD_FEATURE_ADMIN_MODULE_BUILTIN
	new MaAdminModule(0);
#endif
#if BLD_FEATURE_AUTH_MODULE_BUILTIN
	new MaAuthModule(0);
#endif
#if BLD_FEATURE_COPY_MODULE_BUILTIN
	new MaCopyModule(0);
#endif
#if BLD_FEATURE_ESP_MODULE_BUILTIN
	new MaEspModule(0);
#endif
#if BLD_FEATURE_CGI_MODULE_BUILTIN
	new MaCgiModule(0);
#endif
#if BLD_FEATURE_COMPAT_MODULE_BUILTIN
	new MaCompatModule(0);
#endif
#if BLD_FEATURE_EGI_MODULE_BUILTIN
	new MaEgiModule(0);
#endif
#if BLD_FEATURE_EJS_MODULE_BUILTIN
	new MaEjsModule(0);
#endif
#if BLD_FEATURE_PHP_MODULE_BUILTIN
	new MaPhpModule(0);
#endif
#if BLD_FEATURE_SSL_MODULE_BUILTIN
	new MaSslModule(0);
#endif
#if BLD_FEATURE_OPENSSL_MODULE_BUILTIN
	new MaOpenSslModule(0);
#endif
#if BLD_FEATURE_UPLOAD_MODULE_BUILTIN
	new MaUploadModule(0);
#endif
}

////////////////////////////////////////////////////////////////////////////////

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
