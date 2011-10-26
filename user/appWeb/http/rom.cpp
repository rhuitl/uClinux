///
///	@file 	rom.cpp
/// @brief 	ROM File system
///
///	ROM support for systems without disk or flash based file systems. 
///
///	This module provides read-only file retrieval from compiled files images. 
///	Use the httpComp program to compile files into C++ code and then link them
///	into your application. This module uses a hashed symbol table for fast 
///	file lookup.
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

//////////////////////////////////// Code //////////////////////////////////////
#if BLD_FEATURE_ROMFS 

MaRomFileSystem::MaRomFileSystem(MaRomInode *inodeList)
{
	MaRomInode	*ri;
	char		*name;
	int			nchars;

	romInodes = inodeList;
	fileIndex = new MprHashTable(MPR_HTTP_FILES_HASH_SIZE);
	root = mprStrdup("");
	rootLen = strlen(root);

	for (ri = inodeList; ri->path; ri++) {
		name = mprStrdup(ri->path);
		nchars = strlen(name) - 1;
		if (nchars > 0 && (name[nchars] == '/' || name[nchars] == '\\')) {
			name[nchars] = '\0';
		}
		fileIndex->insert(new MaRomHashEntry(name, ri));
		mprFree(name);
	}
}

////////////////////////////////////////////////////////////////////////////////

MaRomFileSystem::~MaRomFileSystem()
{
	mprFree(root);
	delete fileIndex;
}

////////////////////////////////////////////////////////////////////////////////

bool MaRomFileSystem::isDir(char *path)
{
	MaRomInode	*ri;

	if ((ri = (MaRomInode*) lookup(path)) == 0) {
		return 0;
	}
	if (ri->data == 0) {
		return 1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

MaRomInode *MaRomFileSystem::lookup(char *path)
{
	MaRomHashEntry	*hp;

	if (path == 0) {
		return 0;
	}

	//
	//	Before initialization has fully taken place. Convert the relative path
	//	to an absolute one. Assume that the file is in the root directory. 
	//	Must handle ".", "./". Will not handle "/."
	//
	if (*path == '.') {
		if (path[1] == '\0') {
			path = "/";
		} else if (path[1] == '/') {
			path += 1;
		}
	}
	if (strncmp(path, root, rootLen) == 0) {
		path = &path[rootLen];
	}
	hp = (MaRomHashEntry*) fileIndex->lookup(path);
	if (hp == 0) {
		return 0;
	}
	return hp->getInode();
}

////////////////////////////////////////////////////////////////////////////////

MprFile *MaRomFileSystem::newFile()
{
	return new MaRomFile(this);
}

////////////////////////////////////////////////////////////////////////////////

void MaRomFileSystem::setRoot(char *path)
{
	mprFree(root);
	root = mprStrdup(path);
	rootLen = strlen(root);
}

////////////////////////////////////////////////////////////////////////////////

int MaRomFileSystem::stat(char *path, MprFileInfo *info)
{
	MaRomInode	*ri;

	mprAssert(path && *path);

	if ((ri = (MaRomInode*) lookup(path)) == 0) {
		return MPR_ERR_NOT_FOUND;
	}
	memset(info, 0, sizeof(MprFileInfo));
	info->size = ri->size;
	info->mtime = 0;
	info->inode = ri->num;
	if (ri->data == 0) {
		info->isDir = 1;
		info->isReg = 0;
	} else {
		info->isReg = 1;
		info->isDir = 0;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MaRomFile //////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaRomFile::MaRomFile(MaRomFileSystem *rs)
{
	pos = 0;
	romFileSystem = rs;
}

////////////////////////////////////////////////////////////////////////////////

MaRomFile::~MaRomFile()
{
}

////////////////////////////////////////////////////////////////////////////////

int MaRomFile::open(char *path, int flags, int mode)
{
	mprAssert(path && *path);

	if ((inode = romFileSystem->lookup(path)) == 0) {
		return MPR_ERR_NOT_FOUND;
	}
	pos = 0;
	return inode->num;
}

////////////////////////////////////////////////////////////////////////////////

void MaRomFile::close()
{
}

////////////////////////////////////////////////////////////////////////////////

int MaRomFile::read(void *buf, int nBytes)
{
	int		len;

	mprAssert(buf);

	len = min(inode->size - pos, nBytes);
	memcpy(buf, &inode->data[pos], len);
	pos += len;
	return len;
}

////////////////////////////////////////////////////////////////////////////////

int MaRomFile::write(void *buf, int nBytes)
{
	return MPR_ERR_CANT_WRITE;
}

////////////////////////////////////////////////////////////////////////////////

long MaRomFile::lseek(long offset, int origin)
{
	mprAssert(origin == SEEK_SET || origin == SEEK_CUR || origin == SEEK_END);

	switch (origin) {
	case SEEK_CUR:
		pos += offset;
		break;
	case SEEK_END:
		pos = inode->size + offset;
		break;
	default:
		pos = offset;
		break;
	}
	if (pos < 0) {
		errno = EBADF;
		return MPR_ERR_BAD_STATE;
	}
	return pos;
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MaRomHashEntry ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MaRomHashEntry::MaRomHashEntry(char *key, MaRomInode *ri) : MprHashEntry(key)
{
	inode = ri;
}

////////////////////////////////////////////////////////////////////////////////

MaRomInode *MaRomHashEntry::getInode()
{
	return inode;
}

////////////////////////////////////////////////////////////////////////////////
#endif // BLD_FEATURE_ROMFS

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
