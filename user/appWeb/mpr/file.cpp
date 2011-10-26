///
///	@file 	file.cpp
/// @brief 	File system abstraction module
///
///	This modules provides a file system abstraction so that files can be 
///	accessed regardless of the underlying storage mechanism. For example:
///	the MprFileSystem class can be subclassed to support ROM or FLASH file 
///	storage
///
///	@remarks This module is not thread-safe. It is the callers responsibility
///	to perform all thread synchronization.
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

#define 	IN_MPR	1

#include	"mpr.h"

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// MprFileSystem ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprFileSystem::MprFileSystem()
{
}

////////////////////////////////////////////////////////////////////////////////

MprFileSystem::~MprFileSystem()
{
}

////////////////////////////////////////////////////////////////////////////////

bool MprFileSystem::isDir(char *path)
{
	struct stat sbuf;

	if (::stat(path, &sbuf) >= 0) {
		return((bool) ((sbuf.st_mode & S_IFDIR) != 0));
	} else {
		return 0;
	}
}

////////////////////////////////////////////////////////////////////////////////

MprFile *MprFileSystem::newFile()
{
	return new MprFile();
}

////////////////////////////////////////////////////////////////////////////////

void MprFileSystem::setRoot(char *path)
{
}

////////////////////////////////////////////////////////////////////////////////

int MprFileSystem::stat(char *path, MprFileInfo *info)
{
	struct stat	s;

	if (::stat(path, &s) < 0) {
		return -1;
	}
	info->size = s.st_size;
	info->mtime = s.st_mtime;
	info->inode = s.st_ino;
	info->isDir = (s.st_mode & S_IFDIR) != 0;
	info->isReg = (s.st_mode & S_IFREG) != 0;

#if WIN
	//
	//  Work hard on windows to determine if the file is a regular file.
	//	FUTURE -- OPT. Eliminate this CreateFile.
	//
	if (info->isReg) {
		long	fileType, att;

		if ((att = GetFileAttributes(path)) == -1) {
			return -1;
		}
		if (att & (FILE_ATTRIBUTE_REPARSE_POINT |
				FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_ENCRYPTED |
				FILE_ATTRIBUTE_SYSTEM |
				FILE_ATTRIBUTE_OFFLINE)) {
			//
			//	Catch accesses to devices like CON, AUX, NUL, LPT etc
			//	att will be set to ENCRYPTED on Win9X and NT.
			//
			info->isReg = 0;
		}
		if (info->isReg) {
			HANDLE handle;
			handle = CreateFile(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
				0, OPEN_EXISTING, 0, 0);
			if (handle == INVALID_HANDLE_VALUE) {
				info->isReg = 0;
			} else {
				fileType = GetFileType(handle);
				if (fileType == FILE_TYPE_CHAR || fileType == FILE_TYPE_PIPE) {
					info->isReg = 0;
				}
				CloseHandle(handle);
			}
		}
	}
	if (strcmp(path, "nul") == 0) {
		info->isReg = 0;
	}
#else
	if (strcmp(path, "/dev/null") == 0) {
		info->isReg = 0;
	}
#endif
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MprFile ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

MprFile::MprFile()
{
	inBuf = new MprBuf(MPR_BUFSIZE, MPR_BUFSIZE);
	fd = -1;
}

////////////////////////////////////////////////////////////////////////////////

MprFile::~MprFile()
{
	if (fd >= 0) {
		this->close();
		fd = -1;
	}
	delete inBuf;
}

////////////////////////////////////////////////////////////////////////////////

int MprFile::open(char *path, int flags, int mode)
{
	fd = ::open(path, flags, mode);
	return fd;
}

////////////////////////////////////////////////////////////////////////////////

void MprFile::close()
{
	::close(fd);
	fd = -1;
}

////////////////////////////////////////////////////////////////////////////////

int MprFile::read(void *buf, int len)
{
	return ::read(fd, buf, len);
}

////////////////////////////////////////////////////////////////////////////////

int MprFile::write(void *buf, int len)
{
	return ::write(fd, buf, len);
}

////////////////////////////////////////////////////////////////////////////////

long MprFile::lseek(long offset, int origin)
{
	return ::lseek(fd, offset, origin);
}

////////////////////////////////////////////////////////////////////////////////

char *MprFile::gets(char *buf, int bufsize)
{
	int		count, len, c;

	//
	//	Must leave room for null
	//
	count = 0;
	while (--bufsize > 0) {
		if (inBuf->getLength() == 0) {
			inBuf->flush();
			len = read(inBuf->getEnd(), inBuf->getLinearSpace());
			if (len <= 0) {
				return 0;
			}
			inBuf->adjustEnd(len);
			inBuf->addNull();
		}
		if ((c = inBuf->get()) == '\n') {
			buf[count] = '\0';
			return buf;
		}
		buf[count++] = c;
	}
	buf[count] = '\0';
	return buf;
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
