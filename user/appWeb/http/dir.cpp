///
///	@file 	dir.cpp
/// @brief 	Support for Directory directives
///
///	Support authorization on a per-directory basis.
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
///////////////////////////////////// MaDir ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaDir::MaDir()
{
	path = 0;
	pathLen = 0;
	indexName = mprStrdup("index.html");
}

////////////////////////////////////////////////////////////////////////////////

MaDir::MaDir(MaDir *dp, MaAuth *auth)
{
	indexName = mprStrdup(dp->indexName);
	if (auth) {
		inherit(auth);
	}
	path = 0;
	setPath(dp->path);
}

////////////////////////////////////////////////////////////////////////////////

MaDir::~MaDir()
{
	mprFree(indexName);
	mprFree(path);
}

////////////////////////////////////////////////////////////////////////////////

void MaDir::setPath(char *fileName)
{
	char	buf[MPR_MAX_FNAME];
	int		len;

	mprFree(path);
	mprGetFullPathName(buf, sizeof(buf) - 1, fileName);
	len = strlen(buf);
	if (buf[len - 1] != '/') {
		buf[len] = '/';
		buf[++len] = '\0';
	}
	path = mprStrdup(buf);
	pathLen = strlen(path);

#if WIN
	//
	//	Windows is case insensitive for file names. Always map to lower case.
	//
	mprStrLower(path);
#endif
}

////////////////////////////////////////////////////////////////////////////////

void MaDir::setIndex(char *name) 
{ 
	mprFree(indexName);
	indexName = mprStrdup(name); 
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
