///
///	@file 	mprOs.h
/// @brief 	Include O/S headers and smooth out per-O/S differences
///
///	This header is part of the Mbedthis Portable Runtime and aims to include
///	all necessary O/S headers and to unify the constants and declarations 
///	required by Mbedthis products. It can be included by C or C++ programs.
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
////////////////////////////////////////////////////////////////////////////////
#ifndef _h_MPR_OS_HDRS
#define _h_MPR_OS_HDRS 1

#include	"config.h"

////////////////////////////////// CPU Families ////////////////////////////////
//
//	Porters, add your CPU families here. 
//
#define MPR_CPU_UNKNOWN	0
#define MPR_CPU_IX86	1
#define MPR_CPU_PPC 	2
#define MPR_CPU_SPARC 	3
#define MPR_CPU_XSCALE 	4
#define MPR_CPU_ARM 	5
#define MPR_CPU_MIPS 	6

////////////////////////////////// O/S Includes ////////////////////////////////

#if LINUX || SOLARIS
	#include	<sys/types.h>
	#include	<time.h>
	#include	<arpa/inet.h>
	#include	<ctype.h>
	#include	<dlfcn.h>
	#include	<fcntl.h>
	#include	<grp.h> 
	#include	<errno.h>
	#include	<libgen.h>
	#include	<limits.h>
	#include	<netdb.h>
	#include	<net/if.h>
	#include	<netinet/in.h>
	#include	<netinet/tcp.h>
	#include	<netinet/ip.h>
	#include	<pthread.h> 
	#include	<pwd.h> 
	#include	<resolv.h>
	#include	<signal.h>
	#include	<stdarg.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<string.h>
	#include	<syslog.h>
	#include	<sys/ioctl.h>
	#include	<sys/stat.h>
	#include	<sys/param.h>
	#include	<sys/sem.h>
	#include	<sys/shm.h>
	#include	<sys/socket.h>
	#include	<sys/select.h>
	#include	<sys/time.h>
	#include	<sys/times.h>
	#include	<sys/utsname.h>
	#include	<sys/wait.h>
	#include	<unistd.h>

#if LINUX
//	#include	<bits/libc-lock.h>
	#include	<stdint.h>
#endif
#if SOLARIS
	#include	<netinet/in_systm.h>
#endif
#endif // LINUX or SOLARIS

#if MACOSX
	#include	<time.h>
	#include	<arpa/inet.h>
	#include	<ctype.h>
	#include	<fcntl.h>
	#include	<grp.h> 
	#include	<errno.h>
	#include	<libgen.h>
	#include	<limits.h>
	#include	<mach-o/dyld.h>
	#include	<netdb.h>
	#include	<net/if.h>
	#include	<netinet/in_systm.h>
	#include	<netinet/in.h>
	#include	<netinet/tcp.h>
	#include	<netinet/ip.h>
	#include	<pthread.h> 
	#include	<pwd.h> 
	#include	<resolv.h>
	#include	<signal.h>
	#include	<stdarg.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<stdint.h>
	#include	<string.h>
	#include	<syslog.h>
	#include	<sys/ioctl.h>
	#include	<sys/types.h>
	#include	<sys/stat.h>
	#include	<sys/param.h>
	#include 	<sys/resource.h>
	#include	<sys/sem.h>
	#include	<sys/shm.h>
	#include	<sys/socket.h>
	#include	<sys/select.h>
	#include	<sys/time.h>
	#include	<sys/times.h>
	#include	<sys/types.h>
	#include	<sys/utsname.h>
	#include	<sys/wait.h>
	#include	<unistd.h>
#endif // MACOSX

#if WIN
	#include	<ctype.h>
	#include	<conio.h>
	#include	<direct.h>
	#include	<errno.h>
	#include	<fcntl.h>
	#include	<io.h>
	#include	<limits.h>
	#include	<malloc.h>
	#include	<process.h>
	#include	<sys/stat.h>
	#include	<sys/types.h>
	#include	<shlobj.h>
	#include	<stddef.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<string.h>
	#include	<stdarg.h>
	#include	<time.h>
	#define WIN32_LEAN_AND_MEAN
	#include	<windows.h>
	#include	<winbase.h>
#endif // WIN 

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// General Defines ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#define	MAXINT			INT_MAX
#define BITSPERBYTE		8
#define BITS(type)		(BITSPERBYTE * (int) sizeof(type))

#ifndef max
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif

//
//	Set FD_SETSIZE to the maximum number of files (sockets) that you want to
//	support. It is used in select.cpp.
//
//	#ifdef FD_SETSIZE
//		#undef FD_SETSIZE
//	#endif
//	#define FD_SETSIZE		128
//

typedef char	*MprStr;					// Used for dynamic strings

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// Linux Defines ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#if LINUX
	typedef unsigned char uchar;
	__extension__ typedef long long int int64;
	__extension__ typedef unsigned long long int uint64;

	#define closesocket(x)	close(x)
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".so"

	#if BLD_FEATURE_MALLOC
	//
	//	PORTERS: You will need add assembler code for your architecture here
	//	only if you want to use the fast malloc (BLD_FEATURE_MALLOC)
	//
	#if 0
	#define MPR_GET_RETURN(ip)	__builtin_return_address(0)
	#else
		#if MPR_CPU == MPR_CPU_IX86
		#define MPR_GET_RETURN(ip)	\
			asm("movl 4(%%ebp),%%eax ; movl %%eax,%0" : \
				"=g" (ip) : \
				: "eax")
		#endif
	#endif
#endif

#if FUTURE
//	#define mprGetHiResTime(x) __asm__ __volatile__ ("rdtsc" : "=A" (x))
//	extern char *inet_ntoa_r(const struct in_addr in, char *buffer, int buflen);

	//
	//	Atomic functions
	//
	typedef struct { volatile int counter; } mprAtomic_t;

	#if BLD_FEATURE_MULTITHREAD
	#define LOCK "lock ; "
	#else
	#define LOCK ""
	#endif

	static __inline__ void mprAtomicInc(mprAtomic_t* v) {
		__asm__ __volatile__(
			LOCK "incl %0"
			:"=m" (v->counter)
			:"m" (v->counter));
	}

	static __inline__ void mprAtomicDec(mprAtomic_t* v) {
		__asm__ __volatile__(
			LOCK "decl %0"
			:"=m" (v->counter)
			:"m" (v->counter));
	}
#endif
#endif // LINUX 

#if MACOSX
	typedef unsigned long ulong;
	typedef unsigned char uchar;
	__extension__ typedef long long int int64;
	__extension__ typedef unsigned long long int uint64;

	#define closesocket(x)	close(x)
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".dylib"
	#define MSG_NOSIGNAL	0
	#define __WALL          0x40000000
	#define PTHREAD_MUTEX_RECURSIVE_NP  PTHREAD_MUTEX_RECURSIVE

	#if MPR_FEATURE_MALLOC
	//
	//	PORTERS: You will need add assembler code for your architecture here
	//	only if you want to use the fast malloc (MPR_FEATURE_MALLOC)
	//
	#define MPR_GET_RETURN(ip)	__builtin_return_address
	#endif

#if FUTURE
//	#define mprGetHiResTime(x) __asm__ __volatile__ ("rdtsc" : "=A" (x))
//	extern char *inet_ntoa_r(const struct in_addr in, char *buffer, int buflen);

	//
	//	Atomic functions
	//
	typedef struct { volatile int counter; } mprAtomic_t;

	#if MPR_FEATURE_MULTITHREAD
	#define LOCK "lock ; "
	#else
	#define LOCK ""
	#endif

	static __inline__ void mprAtomicInc(mprAtomic_t* v) {
		__asm__ __volatile__(
			LOCK "incl %0"
			:"=m" (v->counter)
			:"m" (v->counter));
	}

	static __inline__ void mprAtomicDec(mprAtomic_t* v) {
		__asm__ __volatile__(
			LOCK "decl %0"
			:"=m" (v->counter)
			:"m" (v->counter));
	}
#endif
#endif // MACOSX

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Windows Defines ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#if WIN
	typedef unsigned char uchar;
	typedef unsigned int uint;
	typedef unsigned long ulong;
	typedef unsigned short ushort;
	typedef __int64 int64;
	typedef unsigned __int64 uint64;

	typedef int 	uid_t;
	typedef void 	*handle;
	typedef char 	*caddr_t;
	typedef long 	pid_t;
	typedef int	 	gid_t;
	typedef ushort 	mode_t;
	typedef void 	*siginfo_t;

	#define HAVE_SOCKLEN_T
	typedef int 	socklen_t;

	#undef R_OK
	#define R_OK	4
	#undef W_OK
	#define W_OK	2
	#undef X_OK
	#define X_OK	1
	#undef F_OK
	#define F_OK	0
	
	#ifndef EADDRINUSE
	#define EADDRINUSE		46
	#endif
	#ifndef EWOULDBLOCK
	#define EWOULDBLOCK		EAGAIN
	#endif
	#ifndef ENETDOWN
	#define ENETDOWN		43
	#endif
	#ifndef ECONNRESET
	#define ECONNRESET		44
	#endif
	#ifndef ECONNREFUSED
	#define ECONNREFUSED	45
	#endif

	#define MSG_NOSIGNAL	0
	#define MPR_BINARY		"b"
	#define MPR_TEXT		"t"

	#define access 	_access
	#define close 	_close
	#define fileno 	_fileno
	#define fstat 	_fstat
	#define getpid 	_getpid
	#define open 	_open
	#define putenv 	_putenv
	#define read 	_read
	#define stat 	_stat
	#define umask 	_umask
	#define unlink 	_unlink
	#define write 	_write
	#define strdup 	_strdup
	#define lseek 	_lseek

	#define mkdir(a,b) 	_mkdir(a)
	#define rmdir(a) 	_rmdir(a)

	#if BLD_FEATURE_MALLOC
	//
	//	PORTERS: You will need add assembler code for your architecture here
	//	only if you want to use the fast malloc (BLD_FEATURE_MALLOC)
	//
	#if MPR_CPU_IX86
	#define MPR_GET_RETURN(ip) \
		__asm {	mov	eax, 4[ebp] } \
		__asm {	mov ip, eax	}
	#endif
	#endif

	#define BITSPERBYTE		8
	#define BITS(type)		(BITSPERBYTE * (int) sizeof(type))
	#define MPR_DLL_EXT		".dll"

	extern void		srand48(long);
	extern long		lrand48(void);
	extern long 	ulimit(int, ...);
	extern long 	nap(long);
	extern uint 	sleep(unsigned int secs);
	extern uid_t 	getuid(void);
	extern uid_t 	geteuid(void);

#endif // WIN 

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Solaris Defines ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#if SOLARIS
	typedef unsigned char uchar;
	typedef long long int int64;
	typedef unsigned long long int uint64;

	#define closesocket(x)	close(x)
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".so"
	#define MSG_NOSIGNAL	0
	#define INADDR_NONE		((in_addr_t) 0xffffffff)
	#define __WALL	0
	#define PTHREAD_MUTEX_RECURSIVE_NP  PTHREAD_MUTEX_RECURSIVE
#endif // SOLARIS 

////////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
}
#endif

#endif // _h_MPR_OS_HDRS 

//
// Local variables:
// tab-width: 4
// c-basic-offset: 4
// End:
// vim:tw=78
// vim600: sw=4 ts=4 fdm=marker
// vim<600: sw=4 ts=4
//
