///
///	@file 	location.cpp
/// @brief 	Implement Location directives.
///
///	Location directives provide authorization and handler matching based on 
///	URL prefixes.
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

#include	"http.h"

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// MaLocation //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaLocation::MaLocation()
{
	flags = 0;
	prefix = 0;
	prefixLen = 0;
	handlerName = 0;
}

////////////////////////////////////////////////////////////////////////////////

MaLocation::MaLocation(MaAuth *auth)
{
	prefix = 0;
	prefixLen = 0;
	handlerName = 0;
	flags = 0;
	inherit(auth);
}

////////////////////////////////////////////////////////////////////////////////

MaLocation::~MaLocation()
{
	mprFree(prefix);
	mprFree(handlerName);
}

////////////////////////////////////////////////////////////////////////////////

void MaLocation::setHandler(char *name)
{
	mprFree(handlerName);
	handlerName = mprStrdup(name);
}

////////////////////////////////////////////////////////////////////////////////

void MaLocation::setPrefix(char *uri)
{
	mprFree(prefix);
	prefix = mprStrdup(uri);
	prefixLen = strlen(prefix);

#if WIN
	//
	//	Windows is case insensitive for file names. Always map to lower case.
	//
	mprStrLower(prefix);
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
