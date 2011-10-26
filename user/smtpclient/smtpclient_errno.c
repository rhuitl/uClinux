/*   ____  __  _ _____ ____     _ _            _   
**  / ___||  \/ |_   _|  _ \___| (_) ___ _ __ | |_ 
**  \___ \| |\/| || | | |_)/ __| | |/ _ \ '_ \| __|
**   ___) | |  | || | |  _| (__| | |  __/ | | | |_ 
**  |____/|_|  |_||_| |_|  \___|_|_|\___|_| |_|\__|
**   
**  SMTPclient -- simple SMTP client
**
**  This program is a minimal SMTP client that takes an email
**  message body and passes it on to a SMTP server (default is the
**  MTA on the local host). Since it is completely self-supporting,
**  it is especially suitable for use in restricted environments.
**
**  ======================================================================
**
**  Copyright (c) 1997 Ralf S. Engelschall, All rights reserved.
**
**  This program is free software; it may be redistributed and/or modified
**  only under the terms of either the Artistic License or the GNU General
**  Public License, which may be found in the SMTP source distribution.
**  Look at the file COPYING. 
**
**  This program is distributed in the hope that it will be useful, but
**  WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  ======================================================================
**
**  smtpclient_errno.c -- errno support
*/

#include <stdio.h>
#include <sys/errno.h>

#include "config.h"

#ifndef HAVE_STRERROR
#ifdef HAVE_SYSERRLIST
extern char *sys_errlist[];
extern int sys_nerr;
#else
static char *sys_errlist[] = { 
/*  0 - NOERROR	*/ "No error status currently",
/*  1 - EPERM	*/ "Not super-user",
/*  2 - ENOENT	*/ "No such file or directory",
/*  3 - ESRCH	*/ "No such process",
/*  4 - EINTR	*/ "Interrupted system call",
/*  5 - EIO	*/ "I/O error",
/*  6 - ENXIO	*/ "No such device or address",
/*  7 - E2BIG	*/ "Arg list too long",
/*  8 - ENOEXEC	*/ "Exec format error",
/*  9 - EBADF	*/ "Bad file number",
/* 10 - ECHILD	*/ "No children",
/* 11 - EAGAIN	*/ "No more processes",
/* 12 - ENOMEM	*/ "Not enough core",
/* 13 - EACCES	*/ "Permission denied",
/* 14 - EFAULT	*/ "Bad address",
/* 15 - ENOTBLK	*/ "Block device required",
/* 16 - EBUSY	*/ "Mount device busy",
/* 17 - EEXIST	*/ "File exists",
/* 18 - EXDEV	*/ "Cross-device link",
/* 19 - ENODEV	*/ "No such device",
/* 20 - ENOTDIR	*/ "Not a directory",
/* 21 - EISDIR	*/ "Is a directory",
/* 22 - EINVAL	*/ "Invalid argument",
/* 23 - ENFILE	*/ "File table overflow",
/* 24 - EMFILE	*/ "Too many open files",
/* 25 - ENOTTY	*/ "Not a typewriter",
/* 26 - ETXTBSY	*/ "Text file busy",
/* 27 - EFBIG	*/ "File too large",
/* 28 - ENOSPC	*/ "No space left on device",
/* 29 - ESPIPE	*/ "Illegal seek",
/* 30 - EROFS	*/ "Read only file system",
/* 31 - EMLINK	*/ "Too many links",
/* 32 - EPIPE	*/ "Broken pipe",
/* 33 - EDOM	*/ "Math arg out of domain of func",
/* 34 - ERANGE	*/ "Math result not representable",
/* 35 - ENOMSG	*/ "No message of desired type",
/* 36 - EIDRM	*/ "Identifier removed"
	};
static int sys_nerr = 37;
#endif
#endif

char *errorstr(int errnum)
{
#ifdef HAVE_STRERROR
	extern char *strerror();
	return strerror(errnum);
#else
	static char buffer[50];
	if (errnum < 0 || errnum >= sys_nerr)  {
	    snprintf(buffer, 50, "ERR-UNKNOWN (%d)", errnum);
	    return(buffer);
	}
	return(sys_errlist[errnum]);
#endif
}

/*EOF*/
