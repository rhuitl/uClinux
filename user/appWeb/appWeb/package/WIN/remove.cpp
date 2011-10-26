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
////////////////////////////////////////////////////////////////////////////////
//
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//
///	@file 	remove.cpp
/// @brief 	Windows removal program
///
///	Must be statically linked with libMpr
///

////////////////////////////////// Includes ////////////////////////////////////

#include	"mpr.h"

//////////////////////////////////// Locals ////////////////////////////////////

#define PROGRAM		BLD_NAME " Removal Program"

static Mpr			*mp;
static MprLogModule	*mod;

static char *fileList[] = {
	"appWeb.conf",
	"*.obj",
	"*.lib",
	"*.dll",
	"*.pdb",
	"*.exe",
	"*.def",
	"*.exp",
	"*.idb",
	"*.plg",
	"*.res",
	"*.ncb",
	"*.opt",
	0
};

////////////////////////////// Forward Declarations ////////////////////////////

static int		initWindow();
static void 	cleanup();
static void 	recursiveRemove(char *dir, char *pattern);
static bool 	match(char *file, char *pat);

//////////////////////////////////// Code //////////////////////////////////////

int APIENTRY WinMain(HINSTANCE inst, HINSTANCE junk, char *args, int junk2)
{
	MprCmdLine		cmdLine(args, "l:rs:");
	MprLogToFile	*logger;
	char			*argp, *logSpec;
	char			dir[MPR_MAX_FNAME], moduleBuf[MPR_MAX_FNAME];
	int				c, errflg, sleepMsecs, removeOk;

	errflg = 0;
	logSpec = 0;
	sleepMsecs = 0;
	removeOk = 0;

	GetModuleFileName(0, moduleBuf, sizeof(moduleBuf) - 1);
	mprGetDirName(dir, sizeof(dir), moduleBuf);
	chdir(dir);

	mp = new Mpr(PROGRAM);
	logger = new MprLogToFile();
	mod = new MprLogModule(PROGRAM);
	mp->addListener(logger);
	mp->addListener(new MprLogToWindow());

	while ((c = cmdLine.next(&argp)) != EOF) {
		switch(c) {
		case 'r':
			removeOk++;
			break;

		case 'l':
			logSpec = argp;
			break;

		case 's':
			sleepMsecs = atoi(argp) * 1000;
			break;

		default:
			errflg++;
			break;
		}
	}

	//
	//	We use removeOk to ensure that someone just running the program won't
	//	do anything bad.
	//
	if (errflg || !removeOk) {
		mprError(MPR_L, MPR_USER, "Bad Usage");
		return FALSE;
	}	

	if (logSpec && mp->setLogSpec(logSpec) < 0) {
		//	FUTURE -- should do more
		delete mp;
		exit(2);
	}
	mprLog(0, mod, "Starting removal\n");


	cleanup();

	//
	//	Some products (services) take a while to exit. This is a convenient
	//	way to pause before removing
	//
	if (sleepMsecs) {
		mprLog(0, mod, "sleeping for %d msec\n", sleepMsecs);
		mprSleep(sleepMsecs);
	}

	mprLog(0, mod, "removal complete\n");
	delete mp;
	delete logger;
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Cleanup temporary files
//

static void cleanup()
{
	char	*file;
	char	home[MPR_MAX_FNAME];
	int		i;

	getcwd(home, sizeof(home) - 1);

	for (i = 0; fileList[i]; i++) {
		file = fileList[i];
		recursiveRemove(home, file);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Remove a file
//

static void recursiveRemove(char *dir, char *pattern)
{
	HANDLE			handle;
	WIN32_FIND_DATA	data;
	char			saveDir[MPR_MAX_FNAME];

	saveDir[sizeof(saveDir) - 1] = '\0';
	getcwd(saveDir, sizeof(saveDir) - 1);

	chdir(dir);
	handle = FindFirstFile("*.*", &data);

	while (FindNextFile(handle, &data)) {
		if (strcmp(data.cFileName, "..") == 0 || 
			strcmp(data.cFileName, ".") == 0) {
			continue;
		}
		if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			recursiveRemove(data.cFileName, pattern);
			//
			//	This will fail if there are files remaining in the directory. 
			//
			mprLog(0, mod, "Removing directory %s\n", data.cFileName);
			RemoveDirectory(data.cFileName);
			continue;
		}
		if (match(data.cFileName, pattern)) {
			mprLog(0, mod, "Delete: %s\n", data.cFileName);
			DeleteFile(data.cFileName);
		}
	}
	FindClose(handle);
	chdir(saveDir);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Simple wild-card matching
//

static bool match(char *file, char *pat)
{
	char	fileBuf[MPR_MAX_PATH], patBuf[MPR_MAX_PATH];
	char	*patExt;
	char	*fileExt;

	mprStrcpy(fileBuf, sizeof(fileBuf), file);
	file = fileBuf;
	mprStrcpy(patBuf, sizeof(patBuf), pat);
	pat = patBuf;

	if (strcmp(file, pat) == 0) {
		return 1;
	}
	if ((fileExt = strrchr(file, '.')) != 0) {
		*fileExt++ = '\0';
	}
	if ((patExt = strrchr(pat, '.')) != 0) {
		*patExt++ = '\0';
	}
	if (*pat == '*' || strcmp(pat, file) == 0) {
		if (patExt && *patExt == '*') {
			return 1;
		} else {
			if (fileExt && strcmp(fileExt, patExt) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
