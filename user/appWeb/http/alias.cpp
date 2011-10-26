///
///	@file 	alias.cpp
/// @brief 	Alias service for aliasing URLs to file storage.
///
///	This module supports the alias directives and mapping URLs to physical 
///	locations. It also performs redirections.
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
/////////////////////////////// MaAliasService /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaAliasService::MaAliasService()
{
#if BLD_FEATURE_MULTITHREAD
	mutex = new MprMutex();
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaAliasService::~MaAliasService()
{
	MaAlias		*ap, *nextAp;

	lock();
	ap = (MaAlias*) aliases.getFirst();
	while (ap) {
		nextAp = (MaAlias*) aliases.getNext(ap);
		delete ap;
		ap = nextAp;
	}
#if BLD_FEATURE_MULTITHREAD
	delete mutex;
#endif
}

////////////////////////////////////////////////////////////////////////////////

int MaAliasService::insertAlias(MaAlias *item)
{
	MaAlias	*ap;
	int		rc;

	//
	//	Sort in reverse collating sequence. Must make sure that /abc/def sorts
	//	before /abc. But we sort redirects with status codes first.
	//
	lock();
	ap = (MaAlias*) aliases.getFirst();
	while (ap) {
		rc = strcmp(item->getPrefix(), ap->getPrefix()); 
		if (rc == 0) {
			unlock();
			return MPR_ERR_ALREADY_EXISTS;
		}
		if (rc > 0) {
			if (item->redirectCode >= ap->redirectCode) {
				ap->insertPrior(item);
				unlock();
				return 0;
			}
		}
		ap = (MaAlias*) aliases.getNext(ap);
	}
	aliases.insert(item);

	unlock();
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Handle Aliases and determine how a URI maps on to physical storage.
//	May redirect if the alias is a redirection. Also the URI 
//

int MaAliasService::mapToStorage(MaRequest *rq, char *uri, char *path, 
	int pathLen, int flags)
{
	MaAlias	*ap;
	MaDir	*dir;
	char	pathBuf[MPR_MAX_FNAME], urlBuf[MPR_HTTP_MAX_URL];
	char	*index, *base;
	int		len, rc;

	lock();
	ap = (MaAlias*) aliases.getFirst();
	while (ap) {
		rc = strncmp(ap->prefix, uri, ap->prefixLen);
		if (rc == 0) {
			if (ap->redirectCode) {
				if (flags & MPR_HTTP_REDIRECT) {
					rq->redirect(ap->redirectCode, ap->aliasName);
					rq->flushOutput(MPR_HTTP_FOREGROUND_FLUSH, 
						MPR_HTTP_FINISH_REQUEST);
				} else {
					mprStrcpy(path, pathLen, ap->aliasName);
				}
				unlock();
				return 0;
			}

			base = &uri[ap->prefixLen];
			if (*base == '/' || 
					ap->aliasName[strlen(ap->aliasName) - 1] == '/') {
				len = mprSprintf(path, pathLen, "%s%s", ap->aliasName, base);
			} else {
				len = mprSprintf(path, pathLen, "%s/%s", ap->aliasName, base);
			}

			if (path[len - 1] == '/' && (flags & MPR_HTTP_ADD_INDEX)) {
				dir = rq->host->findBestDir(path);
				if (dir == 0) {
					mprAssert(0);
					goto next;
				}
				rq->setDir(dir);
				index = dir->getIndex();
				mprAssert(index);
				mprSprintf(pathBuf, sizeof(pathBuf), "%s%s", path, index);
				mprStrcpy(path, pathLen, pathBuf);
				//
				//	Must change the URI and rematch
				//
				mprSprintf(urlBuf, sizeof(urlBuf), "%s%s", uri, index);
				rq->setUri(urlBuf);
				uri = rq->getUri();
				rq->deleteHandlers();

			} else if (rq->isDir(path)) {
				if (flags & MPR_HTTP_REDIRECT) {
					mprSprintf(urlBuf, sizeof(urlBuf), "%s/", uri);
					rq->redirect(301, urlBuf);
					rq->flushOutput(MPR_HTTP_FOREGROUND_FLUSH, 
						MPR_HTTP_FINISH_REQUEST);
					unlock();
					return 0;

				} else if (flags & MPR_HTTP_ADD_INDEX) {
					dir = rq->host->findBestDir(path);
					if (dir == 0) {
						mprAssert(0);
						goto next;
					}
					rq->setDir(dir);
					index = dir->getIndex();
					mprAssert(index);
					mprSprintf(pathBuf, sizeof(pathBuf), "%s%s", path, index);
					mprStrcpy(path, pathLen, pathBuf);
				}
#if WIN
			} else {
				//
				//	Windows will ignore trailing "." and " ". We must reject
				//	here as the URL probably won't match due to the trailing
				//	character and the copyHandler will return the unprocessed
				//	content to the user. Bad.
				//
				int lastc = base[strlen(base) - 1];
				if (lastc == '.' || lastc == ' ') {
					unlock();
					return MPR_ERR_CANT_ACCESS;
				}
#endif
			}
			unlock();
			return 0;
		}
next:
		ap = (MaAlias*) aliases.getNext(ap);
	}
	unlock();
	return MPR_ERR_NOT_FOUND;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// MaAlias ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaAlias::MaAlias(char *prefix, char *aliasName, int code)
{
	this->prefix = mprStrdup(prefix);
	this->prefixLen = strlen(prefix);
	this->aliasName = mprStrdup(aliasName);
	redirectCode = code;

#if WIN
	//
	//	Windows is case insensitive for file names. Always map to lower case.
	//
	mprStrLower(this->prefix);
	mprStrLower(this->aliasName);
#endif
}

////////////////////////////////////////////////////////////////////////////////

MaAlias::~MaAlias()
{
	mprFree(prefix);
	mprFree(aliasName);
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
