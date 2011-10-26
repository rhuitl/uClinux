///
///	@file 	compatApi.h
/// @brief 	GoAhead WebServer "C" language compatability API
///
////////////////////////////////////////////////////////////////////////////////
//
//	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
//	Portions Copyright (c) GoAhead Software Inc. 1998-2000.
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
/////////////////////////////////// Includes ///////////////////////////////////
#ifndef _h_COMPAT_API
#define _h_COMPAT_API 1

#include "mpr.h"

#if BLD_FEATURE_COMPAT_MODULE
#ifdef  __cplusplus
extern "C" {
#endif

///////////////////////////////////// Types ////////////////////////////////////

//
//	Convenient constants
//
#define VALUE_MAX_STRING	4096
#define BUF_MAX				4096
#define SOCKET_BINARY 		O_BINARY
#define SOCKET_RDONLY 		O_RDONLY
#define VALUE_ALLOCATE 		0x1
#define WEBS_NAME 			"Mbedthis-AppWeb/" BLD_VERSION
#define WEBS_SYM_INIT 		64

#if IN_COMPAT_LIBRARY
	typedef class Request *webs_t;
#else
	typedef void		*webs_t;
#endif

typedef char			char_t;
typedef struct _stat	gstat_t;
typedef int				bool_t;

#define	T(s)			s
#define	TSZ(x)			(sizeof(x))
#define	TASTRL(x)		(strlen(x) + 1)

#define gmain		main
#define gasctime	asctime
#define gsprintf	sprintf
#define gprintf		printf
#define gfprintf	fprintf
#define gsscanf		sscanf
#define gvsprintf	vsprintf
#define gstrcpy		strcpy
#define gstrncpy	strncpy
#define gstrncat	strncat
#define gstrlen		strlen
#define gstrcat		strcat
#define gstrcmp		strcmp
#define gstrncmp	strncmp
#define gstricmp	stricmp
#define gstrchr		strchr
#define gstrrchr	strrchr
#define gstrtok		strtok
#define gstrnset	strnset
#define gstrrchr	strrchr
#define gstrstr		strstr
#define gstrtol		strtol

#define gfopen		fopen
#define gopen		open
#define gclose		close
#define gcreat		creat
#define gfgets		fgets
#define gfputs		fputs
#define gfscanf		fscanf
#define ggets		gets
#define glseek		lseek
#define gunlink		unlink
#define gread		read
#define grename		rename
#define gwrite		write
#define gtmpnam		tmpnam
#define gtempnam	tempnam
#define gfindfirst	_findfirst
#define gfinddata_t	_finddata_t
#define gfindnext	_findnext
#define gfindclose	_findclose
#define gstat		stat
#define gaccess		access
#define gchmod		chmod
#define gmkdir		mkdir
#define gchdir		chdir
#define grmdir		rmdir
#define ggetcwd		_getcwd
#define gtolower	towlower
#define gtoupper	towupper
#define gremove		remove
#define gisspace	iswspace
#define gisdigit	iswdigit
#define gisxdigit	iswxdigit
#define gisupper	iswupper
#define gislower	iswlower
#define gisalnum	iswalnum
#define gisalpha	iswalpha
#define gatoi(s)	atoi(s)
#define gctime		ctime
#define ggetenv		getenv
#define gexecvp		execvp

#define B_L			__FILE__, __LINE__
#define a_assert(C)	if (C) ; else mprError(MPR_L, MPR_TRAP, T("%s"), T(#C))

#define balloc(B_L_SPec, num)	 	mprMalloc(num)
#define bfree(B_L_Spec, p) 			mprFree(p)
#define bfreeSafe(B_L_Spec, p) 		mprFree(p)
#define brealloc(B_L_Spec, p, num) 	mprRealloc(p, num)
#define bstrdup(B_L_Spec, s) 		mprStrdup(s)

#define fmtValloc mprAllocVsprintf
#define fmtAlloc mprAllocSprintf
#define fmtStatic mprSprintf

typedef struct {
	ulong			size;
	int				isDir;
	time_t			mtime;
} websStatType;

typedef enum {
	AM_NONE = 0,
	AM_FULL,
	AM_BASIC,
	AM_DIGEST,
	AM_INVALID
} accessMeth_t;

typedef void	(*WebsFormCb)(webs_t wp, char_t *path, char_t *query);
typedef int 	(*WebsAspCb)(int ejid, webs_t wp, int argc, char_t **argv);
typedef int 	(*WebsHandlerCb)(webs_t wp, char_t *urlPrefix, char_t *webDir, 
					int arg, char_t *url, char_t *path, char_t *query);
typedef void	(emfSchedProc)(void *data, int id);

typedef int sym_fd_t;

//
//	Solaris already has a vtype_t
//
#define vtype_t maVtype_t

typedef enum {
	undefined	= 0,	byteint		= 1, shortint	= 2,	integer		= 3,
	hex			= 4,	percent 	= 5, octal		= 6,	big			= 7,
	flag		= 8,	floating	= 9, string 	= 10,	bytes 		= 11,
	symbol 		= 12,	errmsg 		= 13 
} vtype_t;

typedef struct {
	union {
		char	flag;
		char	byteint;
		short	shortint;
		char	percent;
		long	integer;
		long	hex;
		long	octal;
		long	big[2];
		// double	floating;
		char_t	*string;
		char	*bytes;
		char_t	*errmsg;
		void	*symbol;
	} value;
	vtype_t			type;
	unsigned int	valid		: 8;
	unsigned int	allocated	: 8;		/* String was balloced */
} value_t;

typedef struct sym_t {
	struct sym_t	*forw;
	value_t			name;
	value_t			content;
	int				arg;
} sym_t;

extern sym_fd_t	symOpen(int hash_size);
extern void		symClose(sym_fd_t sd);
extern sym_t	*symLookup(sym_fd_t sd, char_t *name);
extern sym_t	*symEnter(sym_fd_t sd, char_t *name, value_t v, int arg);
extern int		symDelete(sym_fd_t sd, char_t *name);
extern sym_t	*symFirstEx(sym_fd_t sd, void **current);
extern sym_t	*symNextEx(sym_fd_t sd, void **current);

////////////////////////////////// Prototypes //////////////////////////////////

extern int		ejArgs(int argc, char_t **argv, char_t *fmt, ...);
extern void 	ejSetResult(int eid, char_t *s);
extern void 	ejSetVar(int eid, char_t *var, char_t *value);

extern int		emfSchedCallback(int delay, emfSchedProc *proc, void *arg);
extern void 	emfUnschedCallback(int id);
extern void 	emfReschedCallback(int id, int delay);

extern int 		websAspDefine(char_t *name, WebsAspCb fn);
extern void 	websDecodeUrl(char_t *decoded, char *token, int len);
extern void 	websDone(webs_t wp, int code);
extern void 	websError(webs_t wp, int code, char_t *msg, ...);
extern char_t 	*websErrorMsg(int code);
extern void 	websFooter(webs_t wp);
extern int 		websFormDefine(char_t *name, WebsFormCb fn);
extern char_t 	*websGetDateString(websStatType *sbuf);
extern char_t 	*websGetRequestLpath(webs_t wp);
extern char_t 	*websGetVar(webs_t wp, char_t *var, char_t *def);
extern void 	websHeader(webs_t wp);
extern int 		websPageOpen(webs_t wp, char_t *fileName, char_t *uri, 
						int mode, int perm);
extern int 		websPageStat(webs_t wp, char_t *fileName, char_t *uri, 
						websStatType* sbuf);
extern void 	websRedirect(webs_t wp, char_t *url);
extern void 	websSetRealm(char_t *realmName);
extern void 	websSetRequestLpath(webs_t wp, char_t *fileName);
extern int 		websUrlHandlerDefine(char_t *urlPrefix, char_t *webDir, 
						int arg, int (*fn)(webs_t wp, char_t *urlPrefix, 
						char_t *webDir, int arg, char_t *url, char_t *path, 
						char_t *query), int flags);
extern int 		websValid(webs_t wp);
extern int 		websValidateUrl(webs_t wp, char_t *path);
extern int 		websWrite(webs_t wp, char_t *fmt, ...);
extern int 		websWriteBlock(webs_t wp, char_t *buf, int nChars);

#if FUTURE
extern int		umOpen();
extern void 	umClose();
extern int		umRestore(char_t *filename);
extern int		umCommit(char_t *filename);
extern int		umAddGroup(char_t *group, short privilege, accessMeth_t am,
						bool_t protect, bool_t disabled);
extern int		umAddUser(char_t *user, char_t *password, char_t *group, 
						bool_t protect, bool_t disabled);
extern int		umDeleteGroup(char_t *group);
extern int		umDeleteUser(char_t *user);
extern char_t 	*umGetFirstGroup();
extern char_t 	*umGetNextGroup(char_t *lastUser);
extern char_t 	*umGetFirstUser();
extern char_t 	*umGetNextUser(char_t *lastUser);
extern accessMeth_t umGetGroupAccessMethod(char_t *group);
extern bool_t 	umGetGroupEnabled(char_t *group);
extern short 	umGetGroupPrivilege(char_t *group);
extern bool_t 	umGetUserEnabled(char_t *user);
extern char_t 	*umGetUserGroup(char_t *user);
extern char_t 	*umGetUserPassword(char_t *user);
extern bool_t 	umGroupExists(char_t *group);
extern int 		umSetGroupAccessMethod(char_t *group, accessMeth_t am);
extern int 		umSetGroupEnabled(char_t *group, bool_t enabled);
extern int 		umSetGroupPrivilege(char_t *group, short privileges);
extern int 		umSetUserEnabled(char_t *user, bool_t enabled);
extern int 		umSetUserGroup(char_t *user, char_t *password);
extern int 		umSetUserPassword(char_t *user, char_t *password);
extern bool_t 	umUserExists(char_t *user);
#endif

extern char_t 	*strlower(char_t *string);
extern char_t 	*strupper(char_t *string);
extern value_t 	valueInteger(long value);
extern value_t 	valueString(char_t *value, int flags);

////////////////////////////////////////////////////////////////////////////////
#ifdef  __cplusplus
} 	// extern "C" 
#endif

#endif // BLD_FEATURE_COMPAT_MODULE
#endif // _h_COMPAT_API 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
