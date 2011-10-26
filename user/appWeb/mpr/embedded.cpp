///
///	@file embedded.cpp 
///	@brief Miscellaneous routines safe for embedded programming
///
///	This module provides safe replacements for the standard library string and
///	formatting routines. It also provides some thread-safe replacements for
///	functions that are only safe when single-threaded.
///
///	@todo FUTURE -- embedded.cpp: 64 bit support for mprSprintf
///
///	@remarks Most routines in this file are not thread-safe. It is the callers 
///	responsibility to perform all thread synchronization.
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
//
//	We need to use the underlying str(cpy) routines to implement our safe
//	alternatives
//
#define 	UNSAFE_FUNCTIONS_OK 1
#define 	IN_MPR	1

#include	"mpr.h"

/////////////////////////////////// Locals /////////////////////////////////////

static uint		lastTimeStamp = 0;		///< Ticks when getTime was last run
static MprTime	sinceBoot;				///< Ticks since boot

static char months[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", 
	"Oct", "Nov", "Dec"
};

static char days[7][4] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

////////////////////////////////// Defines /////////////////////////////////////
//
//	Class definitions
//
#define CLASS_NORMAL	0		// [All other]		Normal characters
#define CLASS_PERCENT	1		// [%]				Begin format
#define CLASS_MODIFIER	2		// [-+ #,]			Modifiers
#define CLASS_ZERO		3		// [0]				Special modifier
#define CLASS_STAR		4		// [*]				Width supplied by arg
#define CLASS_DIGIT		5		// [1-9]			Field widths
#define CLASS_DOT		6		// [.]				Introduce precision
#define CLASS_BITS		7		// [hlL]			Length bits
#define CLASS_TYPE		8		// [cdfinopsSuxX]	Type specifiers

//
//	Format:			%[modifier][width][precision][bits][type]
//
static char classMap[] = {
	//   0  ' '    !     "     #     $     %     &     '
	         2,    0,    0,    2,    0,    1,    0,    0,
	//  07   (     )     *     +     ,     -     .     /
	         0,    0,    4,    2,    2,    2,    6,    0,
	//  10   0     1     2     3     4     5     6     7
	         3,    5,    5,    5,    5,    5,    5,    5,
	//  17   8     9     :     ;     <     =     >     ?
	         5,    5,    0,    0,    0,    0,    0,    0,
	//  20   @     A     B     C     D     E     F     G
	         0,    0,    0,    0,    0,    0,    0,    0,
	//  27   H     I     J     K     L     M     N     O
	         0,    0,    0,    0,    7,    0,    0,    0,
	//  30   P     Q     R     S     T     U     V     W
	         0,    0,    0,    8,    0,    0,    0,    0,
	//  37   X     Y     Z     [     \     ]     ^     _
	         8,    0,    0,    0,    0,    0,    0,    0,
	//  40   '     a     b     c     d     e     f     g
	         0,    0,    0,    8,    8,    0,    8,    0,
	//  47   h     i     j     k     l     m     n     o
	         7,    8,    0,    0,    7,    0,    8,    8,
	//  50   p     q     r     s     t     u     v     w
	         8,    0,    0,    8,    0,    8,    0,    0,
	//  57   x     y     z  
	         8,    0,    0,
};

#define STATE_NORMAL	0				// Normal chars in format string
#define STATE_PERCENT	1				// "%"
#define STATE_MODIFIER	2				// Read flag
#define STATE_WIDTH		3				// Width spec
#define STATE_DOT		4				// "."
#define STATE_PRECISION	5				// Precision spec
#define STATE_BITS		6				// Size spec
#define STATE_TYPE		7				// Data type
#define STATE_COUNT		8

//
//	Format:			%[modifier][width][precision][bits][type]
//
//	#define CLASS_MODIFIER	2		// [-+ #,]			Modifiers
//	#define CLASS_BITS		7		// [hlL]			Length bits
//
static char stateMap[] = {
//     STATES:  Normal  Percent Modifier  Width    Dot    Prec   Bits   Type
// CLASS           0       1       2        3       4       5      6      7
/* Normal   0 */   0,      0,      0,       0,      0,      0,     0,     0,
/* Percent  1 */   1,      0,      1,       1,      1,      1,     1,     1,
/* Modifier 2 */   0,      2,      2,       0,      0,      0,     0,     0,
/* Zero     3 */   0,      2,      2,       3,      0,      5,     0,     0,
/* Star     4 */   0,      3,      3,       0,      0,      0,     0,     0,
/* Digit    5 */   0,      3,      3,       3,      5,      5,     0,     0,
/* Dot      6 */   0,      4,      4,       4,      0,      0,     0,     0,
/* Bits     7 */   0,      6,      6,       6,      6,      6,     6,     0,
/* Types    8 */   0,      7,      7,       7,      7,      7,     7,     0,
};

//
//	Flags
//
#define SPRINTF_LEFT		0x1			// Left align
#define SPRINTF_SIGN		0x2			// Always sign the result
#define SPRINTF_LEAD_SPACE	0x4			// put leading space for +ve numbers
#define SPRINTF_ALTERNATE	0x8			// ??
#define SPRINTF_LEAD_ZERO	0x10		// Zero pad
#define SPRINTF_SHORT		0x20		// 16-bit
#define SPRINTF_LONG		0x40		// 32-bit
#define SPRINTF_LONGLONG	0x80		// 64-bit
#define SPRINTF_COMMA		0x100		// Thousand comma separators
#define SPRINTF_UPPER_CASE	0x200		// As the name says

struct Format {
	MprBuf	*buf;
	int		precision;
	int		radix;
	int		width;
	int		flags;
	int		len;
};

////////////////////////////// Forward Declarations ////////////////////////////
#ifdef __cplusplus
extern "C" {
#endif

static int	getState(char c, int state);
static int	mprSprintfCore(char **s, int maxSize, char *fmt, va_list arg);
static void	outNum(Format *fmt, char *prefix, uint64 val);

static void outFloat(Format *fmt, double value);

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// Safe String Handling /////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int mprStrcpy(char *dest, int destMax, const char *src)
{
	int		len;

	mprAssert(dest);
	mprAssert(destMax > 0);
	mprAssert(src);

	len = strlen(src);
	if (len >= destMax && len > 0) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (len > 0) {
		memcpy(dest, src, len);
		dest[len] = '\0';
	} else {
		*dest = '\0';
		len = 0;
	} 
	return len;
}

////////////////////////////////////////////////////////////////////////////////

int mprAllocStrcpy(char **dest, int destMax, const char *src)
{
	int		len;

	mprAssert(dest);
	mprAssert(destMax > 0);
	mprAssert(src);

	len = strlen(src);
	if (len >= destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (len > 0) {
		*dest = (char*) mprMalloc(len);
		memcpy(*dest, src, len);
		(*dest)[len] = '\0';
	} else {
		*dest = (char*) mprMalloc(1);
		*dest = '\0';
		len = 0;
	} 
	return len;
}

////////////////////////////////////////////////////////////////////////////////

int mprMemcpy(char *dest, int destMax, const char *src, int nbytes)
{
	mprAssert(dest);
	mprAssert(destMax > nbytes);
	mprAssert(src);
	mprAssert(nbytes > 0);

	if (nbytes > destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (nbytes > 0) {
		memcpy(dest, src, nbytes);
		return nbytes;
	} else {
		return 0;
	}
}

////////////////////////////////////////////////////////////////////////////////

int mprAllocMemcpy(char **dest, int destMax, const char *src, int nbytes)
{
	mprAssert(dest);
	mprAssert(src);
	mprAssert(nbytes > 0);
	mprAssert(destMax >= nbytes);

	if (nbytes > destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	if (nbytes > 0) {
		*dest = (char*) mprMalloc(nbytes);
		memcpy(*dest, src, nbytes);
	} else {
		*dest = (char*) mprMalloc(1);
	}
	return nbytes;
}

////////////////////////////////////////////////////////////////////////////////

static int mprCoreStrcat(int alloc, char **destp, int destMax, int existingLen, 
	const char *delim, const char *src, va_list args)
{
	va_list		ap;
	char		*dest, *str, *dp;
	int			sepLen, addBytes, required;

	mprAssert(destp);
	mprAssert(destMax > 0);
	mprAssert(src);

	dest = *destp;
	sepLen = (delim) ? strlen(delim) : 0;

	ap = args;
	addBytes = 0;
	str = (char*) src;
	while (str) {
		addBytes += strlen(str) + sepLen;
		str = va_arg(ap, char*);
	}

	if (existingLen > 0) {
		addBytes += sepLen;
	}
	required = existingLen + addBytes + 1;
	if (required >= destMax) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}

	if (alloc) {
		if (dest == 0) {
			dest = (char*) mprMalloc(required);
		} else {
			dest = (char*) mprRealloc(dest, required);
		}
	} else {
		dest = (char*) *destp;
	}

	dp = &dest[existingLen];
	if (delim) {
		strcpy(dp, delim);
		dp += sepLen;
	}

	if (addBytes > 0) {
		ap = args;
		str = (char*) src;
		while (str) {
			strcpy(dp, str);
			dp += strlen(str);
			if (delim) {
				strcpy(dp, delim);
				dp += sepLen;
			}
			str = va_arg(ap, char*);
		}
	} else if (dest == 0) {
		dest = (char*) mprMalloc(1);
	} 
	*dp = '\0';

	*destp = dest;
	mprAssert(dp < &dest[required]);
	return required - 1;
}

////////////////////////////////////////////////////////////////////////////////

int mprStrcat(char *dest, int destMax, const char *delim, const char *src, ...)
{
	va_list		ap;
	int			rc;

	va_start(ap, src);
	rc = mprCoreStrcat(0, &dest, destMax, 0, delim, src, ap);
	va_end(ap);
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

int mprAllocStrcat(char **destp, int destMax, const char *delim, 
	const char *src, ...)
{
	va_list		ap;
	int			rc;

	*destp = 0;
	va_start(ap, src);
	rc = mprCoreStrcat(1, destp, destMax, 0, delim, src, ap);
	va_end(ap);
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

int mprReallocStrcat(char **destp, int destMax, int existingLen, 
	const char *delim, const char *src,...)
{
	va_list		ap;
	int			rc;

	va_start(ap, src);
	rc = mprCoreStrcat(1, destp, destMax, existingLen, delim, src, ap);
	va_end(ap);
	return rc;
}

////////////////////////////////////////////////////////////////////////////////

int mprStrlen(char *src, int max)
{
	int		len;

	len = strlen(src);
	if (len >= max) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	return len;
}

////////////////////////////////////////////////////////////////////////////////

char* mprStrTrim(char *str, char c)
{
	if (str == 0) {
		return str;
	}
	while (*str == c) {
		str++;
	}
	while (str[strlen(str) - 1] == c) {
		str[strlen(str) - 1] = '\0';
	}
	return str;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Map a string to lower case (overwrites original string)
//

char *mprStrLower(char *str)
{
	char	*cp;

	mprAssert(str);

	if (str == 0) {
		return 0;
	}

	for (cp = str; *cp; cp++) {
		if (isupper(*cp)) {
			*cp = (char) tolower(*cp);
		}
	}
	return str;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Map a string to upper case (overwrites buffer)
//

char *mprStrUpper(char *str)
{
	char	*cp;

	mprAssert(str);
	if (str == 0) {
		return 0;
	}

	for (cp = str; *cp; cp++) {
		if (islower(*cp)) {
			*cp = (char) toupper(*cp);
		}
	}
	return str;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Case insensitive string comparison. Stop at the end of str1.
//

int mprStrCmpAnyCase(char *str1, char *str2)
{
	int		rc;

	if (str1 == 0 || str2 == 0) {
		return -1;
	}
	if (str1 == str2) {
		return 0;
	}

	for (rc = 0; *str1 && rc == 0; str1++, str2++) {
		rc = tolower(*str1) - tolower(*str2);
	}
	if (*str2) {
		return -1;
	}
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Case insensitive string comparison. Limited by length
//

int mprStrCmpAnyCaseCount(char *str1, char *str2, int len)
{
	int		rc;

	if (str1 == 0 || str2 == 0) {
		return -1;
	}
	if (str1 == str2) {
		return 0;
	}

	for (rc = 0; len-- > 0 && *str1 && rc == 0; str1++, str2++) {
		rc = tolower(*str1) - tolower(*str2);
	}
	return rc;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the last portion of a pathname
//

char *mprGetBaseName(char *name)
{
	char *cp;

	cp = strrchr(name, '/');

	if (cp == 0) {
		cp = strrchr(name, '\\');
		if (cp == 0) {
			return name;
		}
	} 
	if (cp == name) {
		if (cp[1] == '\0') {
			return name;
		}
	} else {
		if (cp[1] == '\0') {
			return "";
		}
	}
	return &cp[1];
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the directory portion of a pathname into the users buffer.
//

int mprGetDirName(char *buf, int bufsize, char *path)
{
	char	*cp;
	int		dlen;

	mprAssert(path);
	mprAssert(buf);
	mprAssert(bufsize > 0);

	cp = strrchr(path, '/');
	if (cp == 0) {
#if WIN
		cp = strrchr(path, '\\');
		if (cp == 0)
#endif
		{
			buf[0] = '\0';
			return 0;
		}
	}

	if (cp == path && cp[1] == '\0') {
		strcpy(buf, ".");
		return 0;
	}

	dlen = cp - path;
	if (dlen < bufsize) {
		if (dlen == 0) {
			dlen++;
		}
		mprMemcpy(buf, bufsize, path, dlen);
		buf[dlen] = '\0';
		return 0;
	}
	return MPR_ERR_WONT_FIT;
}

////////////////////////////////////////////////////////////////////////////////

char *mprMakeTempFileName(char *buf, int bufsize, char *prefix, bool useTemp)
{
	static int seed = 0;

#if LINUX || MACOSX  || SOLARIS
#if FUTURE
	mprSprintf(buf, bufsize, "%s_mpr_%d_XXXXXX", prefix, seed++);
	mkstemp(buf);
#else
	int fd;
	mprLock();
	do {
		mprSprintf(buf, bufsize, "%s/MPR_%s_%d_%d.tmp", 
			(useTemp) ? "/tmp" : "", prefix, getpid(), seed++);
	} while ((fd = open(buf, O_CREAT | O_EXCL, 0664)) < 0);
	close(fd);
	mprUnlock();
#endif
#elif WIN
	char *temp = getenv("TEMP");
	if (useTemp && temp && *temp) {
		for (char *cp = temp; *cp; cp++) {
			if (*cp == '\\') {
				*cp = '/';
			}
		}
		mprSprintf(buf, bufsize, "%s/s_mpr_%d_XXXXXX", temp, prefix, seed++);
	} else {
		mprSprintf(buf, bufsize, "%s_mpr_%d_XXXXXX", prefix, seed++);
	}
	mktemp(buf);
#else
#endif
	return buf;
}

////////////////////////////////////////////////////////////////////////////////

char *mprInetNtoa(char *buffer, int bufsize, const struct in_addr in)
{
#if HAVE_NTOA_R
	inet_ntoa_r(in, buffer, bufsize);
#else
	uchar	*cp;
	//	MOB -- this is not portable
	cp = (uchar*) &in;
	mprSprintf(buffer, bufsize, "%d.%d.%d.%d", cp[0], cp[1], cp[2], cp[3]);
#endif
	return buffer;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Sleep. Period given in milliseconds.
//

void mprSleep(int milliseconds)
{
#if LINUX || MACOSX || SOLARIS
	struct timespec	timeout;
	int				rc;

	mprAssert(milliseconds >= 0);
	timeout.tv_sec = milliseconds / 1000;
	timeout.tv_nsec = (milliseconds % 1000) * 1000000;
	do {
		rc = nanosleep(&timeout, 0);
	} while (rc < 0 && errno == EINTR);
#endif
#if WIN
	Sleep(milliseconds);
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the current time (milliseconds). This is NOT time-of-day.
//	Also fill out the time structure if non-null
//

int mprGetTime(MprTime *tp)
{
	MprTime	local;
	long	clockTicksPerSec;
	uint	ticks, elapsedMsec, elapsedTicks;
	int		tval;

	if (tp == 0) {
		tp = &local;
	}
#if BLD_FEATURE_MULTITHREAD
	mpr->timeLock();
#endif

#if WIN
	ticks = GetTickCount();
	clockTicksPerSec = 1000;
#endif
#if LINUX || MACOSX || SOLARIS
	struct tms		junk;
	ticks = times(&junk);
	clockTicksPerSec = sysconf(_SC_CLK_TCK);
#endif

	if (ticks < lastTimeStamp) {
		elapsedTicks = (0xFFFFFFFF - lastTimeStamp) + 1 + ticks;
	} else {
		elapsedTicks = ticks - lastTimeStamp;
	}
	lastTimeStamp = ticks;

	//
	//	Convert to milliseconds
	//
	elapsedMsec = (elapsedTicks * 1000) / clockTicksPerSec;

	sinceBoot.usec += ((elapsedMsec % 1000) * 1000);
	if (sinceBoot.usec >= 1000000) {
		sinceBoot.usec -= 1000000;
		sinceBoot.sec += 1 + (elapsedMsec / 1000);
	} else {
		sinceBoot.sec += (elapsedMsec / 1000);
	}

	tp->usec = sinceBoot.usec;			// Note this is micro-secs
	tp->sec = sinceBoot.sec;
	tval = (tp->sec * 1000) + tp->usec / 1000;

#if BLD_FEATURE_MULTITHREAD
	mpr->timeUnlock();
#endif
	return tval;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Thread-safe wrapping of localtime 
//
#undef localtime
#undef localtime_r

struct tm *mprLocaltime(time_t *now, struct tm *timep)
{
#if LINUX || MACOSX || SOLARIS
	localtime_r(now, timep);
#else
	struct tm *tbuf;
	mprLock();
	tbuf = localtime(now);
	*timep = *tbuf;
	mprUnlock();
#endif
	return timep;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Thread-safe wrapping of gmtime 
//
#undef gmtime
#undef gmtime_r

struct tm *mprGmtime(time_t *now, struct tm *timep)
{
#if LINUX || MACOSX || SOLARIS
	gmtime_r(now, timep);
#else
	struct tm *tbuf;
	tbuf = gmtime(now);
	*timep = *tbuf;
#endif
	return timep;
}

///////////////////////////////////////////////////////////////////////////////
//
//	Thread-safe wrapping of ctime
//
#undef ctime
#undef ctime_r

int mprCtime(const time_t *timer, char *buf, int bufsize)
{
	char	*cp;
		
	mprAssert(buf);
#if LINUX || MACOSX || SOLARIS
	char	localBuf[80];
	cp = ctime_r(timer, localBuf);
	if ((int) strlen(cp) >= bufsize) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	mprStrcpy(buf, bufsize, cp);
#else
	mprLock();
	cp = ctime(timer);
	if ((int) strlen(cp) >= bufsize) {
		mprAssert(0);
		mprUnlock();
		return MPR_ERR_WONT_FIT;
	}
	mprStrcpy(buf, bufsize, cp);
	mprUnlock();
#endif
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
//	Thread-safe wrapping of asctime
//
#undef asctime
#undef asctime_r

int mprAsctime(const struct tm *timeptr, char *buf, int bufsize)
{
	char	*cp;

#if LINUX || MACOSX || SOLARIS
	char	localBuf[80];
	cp = asctime_r(timeptr, localBuf);
	if ((int) strlen(cp) >= bufsize) {
		mprAssert(0);
		return MPR_ERR_WONT_FIT;
	}
	mprStrcpy(buf, bufsize, cp);
#else
	mprAssert(buf);
	mprLock();
	cp = asctime(timeptr);
	if ((int) strlen(cp) >= bufsize) {
		mprAssert(0);
		mprUnlock();
		return MPR_ERR_WONT_FIT;
	}
	mprStrcpy(buf, bufsize, cp);
	mprUnlock();
#endif
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
//	Thread-safe RFC822 dates (Eg: "Fri, 07 Jan 2003 12:12:21 GMT")
//

int mprRfcTime(char *buf, int size, const struct tm *timer)
{
    char	*dayp, *monthp;
    int		year;

	if (size < 30) {
		return MPR_ERR_WONT_FIT;
	}
    dayp = &days[timer->tm_wday][0];
    *buf++ = *dayp++;
    *buf++ = *dayp++;
    *buf++ = *dayp++;
    *buf++ = ',';
    *buf++ = ' ';

    *buf++ = timer->tm_mday / 10 + '0';
    *buf++ = timer->tm_mday % 10 + '0';
    *buf++ = ' ';

    monthp = &months[timer->tm_mon][0];
    *buf++ = *monthp++;
    *buf++ = *monthp++;
    *buf++ = *monthp++;
    *buf++ = ' ';

    year = 1900 + timer->tm_year;
    /* This routine isn't y10k ready. */
    *buf++ = year / 1000 + '0';
    *buf++ = year % 1000 / 100 + '0';
    *buf++ = year % 100 / 10 + '0';
    *buf++ = year % 10 + '0';
    *buf++ = ' ';

    *buf++ = timer->tm_hour / 10 + '0';
    *buf++ = timer->tm_hour % 10 + '0';
    *buf++ = ':';
    *buf++ = timer->tm_min / 10 + '0';
    *buf++ = timer->tm_min % 10 + '0';
    *buf++ = ':';
    *buf++ = timer->tm_sec / 10 + '0';
    *buf++ = timer->tm_sec % 10 + '0';
    *buf++ = ' ';

    *buf++ = 'G';
    *buf++ = 'M';
    *buf++ = 'T';
    *buf++ = 0;
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Thread-safe wrapping of strtok. Note "str" is modifed as per strtok()
//

char *mprStrTok(char *str, const char *delim, char **tok)
{
	char	*start, *end;
	int		i;

	start = str ? str : *tok;

	if (start == 0) {
		return 0;
	}
	
	i = strspn(start, delim);
	start += i;
	if (*start == '\0') {
		*tok = 0;
		return 0;
	}
	end = strpbrk(start, delim);
	if (end) {
		*end++ = '\0';
		i = strspn(end, delim);
		end += i;
	}
	*tok = end;
	return start;
}

///////////////////////////////////////////////////////////////////////////////

char *mprGetWordTok(char *buf, int bufsize, char *str, const char *delim, 
	char **tok)
{
	char	*start, *end;
	int		i, len;

	start = str ? str : *tok;

	if (start == 0) {
		return 0;
	}
	
	i = strspn(start, delim);
	start += i;
	if (*start =='\0') {
		*tok = 0;
		return 0;
	}
	end = strpbrk(start, delim);
	if (end) {
		len = min(end - start, bufsize - 1);
		mprMemcpy(buf, bufsize, start, len);
		buf[len] = '\0';
	} else {
		if (mprStrcpy(buf, bufsize, start) < 0) {
			buf[bufsize - 1] = '\0';
			return 0;
		}
		buf[bufsize - 1] = '\0';
	}
	*tok = end;
	return buf;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Printf with a static buffer. Used internally only. WILL NOT MALLOC.

int mprStaticPrintf(char *fmt, ...)
{
	va_list		ap;
	char		buf[MPR_MAX_STRING];
	char		*bufp;
	int			len;

	va_start(ap, fmt);
	bufp = buf;
	len = mprSprintfCore(&bufp, MPR_MAX_STRING, fmt, ap);
	va_end(ap);
	if (len >= 0) {
		write(1, buf, len);
	}
	return len;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Replacement for printf
//

int mprPrintf(char *fmt, ...)
{
	va_list		ap;
	char		buf[MPR_MAX_STRING];
	int			len;

	va_start(ap, fmt);
	len = mprVsprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len >= 0) {
		write(1, buf, len);
	}
	return len;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Replacement for fprintf, but writes to a file descriptor.
//

int mprFprintf(int fd, char *fmt, ...)
{
	va_list		ap;
	char		buf[MPR_MAX_STRING];
	int			len;

	va_start(ap, fmt);
	len = mprVsprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len >= 0) {
		len = write(fd, buf, len);
	}
	return len;
}

////////////////////////////////////////////////////////////////////////////////

int mprSprintf(char *buf, int n, char *fmt, ...)
{
	va_list		ap;
	int			result;

	mprAssert(buf);
	mprAssert(fmt);
	mprAssert(n > 0);

	va_start(ap, fmt);
	result = mprSprintfCore(&buf, n, fmt, ap);
	va_end(ap);
	return result;
}

////////////////////////////////////////////////////////////////////////////////

int mprVsprintf(char *buf, int n, char *fmt, va_list arg)
{
	mprAssert(buf);
	mprAssert(fmt);
	mprAssert(n > 0);

	return mprSprintfCore(&buf, n, fmt, arg);
}

////////////////////////////////////////////////////////////////////////////////

int mprAllocSprintf(char **s, int n, char *fmt, ...)
{
	va_list	ap;
	int		result;

	mprAssert(s);
	mprAssert(fmt);

	*s = 0;
	va_start(ap, fmt);
	result = mprSprintfCore(s, n, fmt, ap);
	va_end(ap);
	return result;
}

////////////////////////////////////////////////////////////////////////////////

int mprAllocVsprintf(char **s, int n, char *fmt, va_list arg)
{
	mprAssert(s);
	mprAssert(fmt);

	*s = 0;
	return mprSprintfCore(s, n, fmt, arg);
}

////////////////////////////////////////////////////////////////////////////////

static int getState(char c, int state)
{
	int		chrClass;

	if (c < ' ' || c > 'z') {
		chrClass = CLASS_NORMAL;
	} else {
		mprAssert((c - ' ') < (int) sizeof(classMap));
		chrClass = classMap[(c - ' ')];
	}
	mprAssert((chrClass * STATE_COUNT + state) < (int) sizeof(stateMap));
	state = stateMap[chrClass * STATE_COUNT + state];
	return state;
}

////////////////////////////////////////////////////////////////////////////////

static int mprSprintfCore(char **bufPtr, int maxSize, char *spec, va_list arg)
{
	Format		fmt;
	MprBuf		buf;
	char		*cp;
	char		c;
	char		*sValue;
	int64		iValue;
	uint64		uValue;
	int			count, i, len, state;

	mprAssert(bufPtr);
	mprAssert(spec);

	if (*bufPtr != 0) {
		buf.setBuf((uchar*) *bufPtr, maxSize);
	} else {
		if (maxSize <= 512) {
			buf.setBuf(maxSize, maxSize);
		} else {
			buf.setBuf(MPR_DEFAULT_ALLOC, maxSize);
		}
	}

	state = STATE_NORMAL;
	fmt.buf = &buf;
	fmt.len = 0;

	while ((c = *spec++) != '\0') {
		state = getState(c, state);

		switch (state) {
		case STATE_NORMAL:
			buf.put(c);
			break;

		case STATE_PERCENT:
			fmt.precision = -1;
			fmt.width = 0;
			fmt.flags = 0;
			break;

		case STATE_MODIFIER:
			switch (c) {
			case '+':
				fmt.flags |= SPRINTF_SIGN;
				break;
			case '-':
				fmt.flags |= SPRINTF_LEFT;
				break;
			case '#':
				fmt.flags |= SPRINTF_ALTERNATE;
				break;
			case '0':
				fmt.flags |= SPRINTF_LEAD_ZERO;
				break;
			case ' ':
				fmt.flags |= SPRINTF_LEAD_SPACE;
				break;
			case ',':
				fmt.flags |= SPRINTF_COMMA;
				break;
			}
			break;

		case STATE_WIDTH:
			if (c == '*') {
				fmt.width = va_arg(arg, int);
				if (fmt.width < 0) {
					fmt.width = -fmt.width;
					fmt.flags |= SPRINTF_LEFT;
				}
			} else {
				while (isdigit((int)c)) {
					fmt.width = fmt.width * 10 + (c - '0');
					c = *spec++;
				}
				spec--;
			}
			break;

		case STATE_DOT:
			fmt.precision = 0;
			fmt.flags &= ~SPRINTF_LEAD_ZERO;
			break;

		case STATE_PRECISION:
			if (c == '*') {
				fmt.precision = va_arg(arg, int);
			} else {
				while (isdigit((int)c)) {
					fmt.precision = fmt.precision * 10 + (c - '0');
					c = *spec++;
				}
				spec--;
			}
			break;

		case STATE_BITS:
			switch (c) {
			case 'L':
				fmt.flags |= SPRINTF_LONGLONG;			// 64 bit
				break;

			case 'l':
				fmt.flags |= SPRINTF_LONG;
				break;

			case 'h':
				fmt.flags |= SPRINTF_SHORT;
				break;
			}
			break;

		case STATE_TYPE:
			switch (c) {
			case 'f':
				outFloat(&fmt, (double) va_arg(arg, double));
				break;

			case 'c':
				buf.put((char) va_arg(arg, int));
				break;

			case 's':
			case 'S':
				sValue = va_arg(arg, char*);
				if (sValue == 0) {
					sValue = "(NULL)";
					len = strlen(sValue);
				} else if (fmt.flags & SPRINTF_ALTERNATE) {
					sValue++;
					len = (int) *sValue;
				} else if (fmt.precision >= 0) {
					//
					//	Can't use strlen(), the string may not have a null
					//
					cp = sValue;
					for (len = 0; len < fmt.precision; len++) {
						if (*cp++ == '\0') {
							break;
						}
					}
				} else {
					len = strlen(sValue);
				}
				if (!(fmt.flags & SPRINTF_LEFT)) {
					for (i = len; i < fmt.width; i++) {
						buf.put((char) ' ');
					}
				}
				for (i = 0; i < len && *sValue; i++) {
					buf.put(*sValue++);
				}
				if (fmt.flags & SPRINTF_LEFT) {
					for (i = len; i < fmt.width; i++) {
						buf.put((char) ' ');
					}
				}
				break;

			case 'i':
				;
			case 'd':
				fmt.radix = 10;
				if (fmt.flags & SPRINTF_SHORT) {
					iValue = (short) va_arg(arg, int);
				} else if (fmt.flags & SPRINTF_LONG) {
					iValue = va_arg(arg, long);
				} else if (fmt.flags & SPRINTF_LONGLONG) {
					iValue = va_arg(arg, int64);
				} else {
					iValue = va_arg(arg, int);
				}
				if (iValue >= 0) {
					if (fmt.flags & SPRINTF_LEAD_SPACE) {
						outNum(&fmt, " ", iValue);
					} else if (fmt.flags & SPRINTF_SIGN) {
						outNum(&fmt, "+", iValue);
					} else {
						outNum(&fmt, 0, iValue);
					}
				} else {
					outNum(&fmt, "-", -iValue);
				}
				break;

			case 'X':
				fmt.flags |= SPRINTF_UPPER_CASE;
				//	Fall through 
			case 'o':
			case 'x':
			case 'u':
				if (fmt.flags & SPRINTF_SHORT) {
					uValue = (ushort) va_arg(arg, uint);
				} else if (fmt.flags & SPRINTF_LONG) {
					uValue = va_arg(arg, ulong);
				} else if (fmt.flags & SPRINTF_LONGLONG) {
					uValue = va_arg(arg, uint64);
				} else {
					uValue = va_arg(arg, uint);
				}
				if (c == 'u') {
					fmt.radix = 10;
					outNum(&fmt, 0, uValue);
				} else if (c == 'o') {
					fmt.radix = 8;
					if (fmt.flags & SPRINTF_ALTERNATE && uValue != 0) {
						outNum(&fmt, "0", uValue);
					} else {
						outNum(&fmt, 0, uValue);
					}
				} else {
					fmt.radix = 16;
					if (fmt.flags & SPRINTF_ALTERNATE && uValue != 0) {
						if (c == 'X') {
							outNum(&fmt, "0X", uValue);
						} else {
							outNum(&fmt, "0x", uValue);
						}
					} else {
						outNum(&fmt, 0, uValue);
					}
				}
				break;

			case 'n':		// Count of chars seen thus far
				if (fmt.flags & SPRINTF_SHORT) {
					short *count = va_arg(arg, short*);
					*count = buf.getLength();
				} else if (fmt.flags & SPRINTF_LONG) {
					long *count = va_arg(arg, long*);
					*count = buf.getLength();
				} else {
					int *count = va_arg(arg, int *);
					*count = buf.getLength();
				}
				break;

			case 'p':		// Pointer
				uValue = (uint64) (uint) va_arg(arg, void*);
				fmt.radix = 16;
				outNum(&fmt, "0x", uValue);
				break;

			default:
				buf.put(c);
			}
		}
	}
	buf.addNull();

	count = buf.getLength();
	if (*bufPtr == 0) {
		*bufPtr = (char*) buf.takeBuffer();
	}
	return count;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Output a number. Use 64 bits universally. Slower but smaller code.
//

static void outNum(Format *fmt, char *prefix, uint64 value)
{
	MprBuf	*bp;
	char	numBuf[64];
	char	*cp;
	char	*endp;
	char	c;
	int		letter, len, leadingZeros, i, fill;

	bp = fmt->buf;
	endp = &numBuf[sizeof(numBuf) - 1];
	*endp = '\0';
	cp = endp;

	//
	//	Convert to ascii
	//
	if (fmt->radix == 16) {
		do {
			letter = (int) (value % fmt->radix);
			if (letter > 9) {
				if (fmt->flags & SPRINTF_UPPER_CASE) {
					letter = 'A' + letter - 10;
				} else {
					letter = 'a' + letter - 10;
				}
			} else {
				letter += '0';
			}
			*--cp = letter;
			value /= fmt->radix;
		} while (value > 0);
	} else if (fmt->flags & SPRINTF_COMMA) {
		i = 1;
		do {
			*--cp = '0' + (int) (value % fmt->radix);
			value /= fmt->radix;
			if ((i++ % 3) == 0 && value > 0) {
				*--cp = ',';
			}
		} while (value > 0);
	} else {
		do {
			*--cp = '0' + (int) (value % fmt->radix);
			value /= fmt->radix;
		} while (value > 0);
	}

	len = endp - cp;
	fill = fmt->width - len;

	if (prefix != 0) {
		fill -= strlen(prefix);
	}
	leadingZeros = (fmt->precision > len) ? fmt->precision - len : 0;
	fill -= leadingZeros;

	if (!(fmt->flags & SPRINTF_LEFT)) {
		c = (fmt->flags & SPRINTF_LEAD_ZERO) ? '0': ' ';
		for (i = 0; i < fill; i++) {
			bp->put(c);
		}
	}
	if (prefix != 0) {
		bp->put(prefix);
	}
	for (i = 0; i < leadingZeros; i++) {
		bp->put('0');
	}
	bp->put(cp);
	if (fmt->flags & SPRINTF_LEFT) {
		for (i = 0; i < fill; i++) {
			bp->put(' ');
		}
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Output a floating point number
//

static void outFloat(Format *fmt, double value)
{
#if 0
	MprBuf	*bp;
	char	numBuf[64];
	char	*cp;
	char	*endp;
	char	c;
	int		letter, len, leadingZeros, i, fill, width, precision;

	bp = fmt->buf;

	endp = &numBuf[sizeof(numBuf) - 1];
	*endp = '\0';
	cp = endp;

	precision = fmt->precision;
	if (precision < 0) {
		precision = 6;
//	} else if (precision > (sizeof(numBuf) - 1)) {
//		precision = (sizeof(numBuf) - 1);
	}
	width = min(fmt->width, sizeof(numBuf) - 1);

	//
	//	Convert to ascii
	//
	while (width > 0) {
		*cp++ = 



		*--cp = '0' + (int) (value % 10);
		value /= 10;
		if (value < 0) {
		}
	}
	len = endp - cp;
	fill = fmt->width - len;

	if (prefix != 0) {
		fill -= strlen(prefix);
	}
	leadingZeros = (fmt->precision > len) ? fmt->precision - len : 0;
	fill -= leadingZeros;

	if (!(fmt->flags & SPRINTF_LEFT)) {
		c = (fmt->flags & SPRINTF_LEAD_ZERO) ? '0': ' ';
		for (i = 0; i < fill; i++) {
			bp->put(c);
		}
	}
	if (prefix != 0) {
		bp->put(prefix);
	}
	for (i = 0; i < leadingZeros; i++) {
		bp->put('0');
	}
	bp->put(cp);
	if (fmt->flags & SPRINTF_LEFT) {
		for (i = 0; i < fill; i++) {
			bp->put(' ');
		}
	}
#endif
	char	numBuf[64];
	sprintf(numBuf, "%*.*f", fmt->width, fmt->precision, value);
	fmt->buf->put(numBuf);
}

////////////////////////////////////////////////////////////////////////////////
//
//	Format a number as a string. FUTURE -- reverse args to be standard.
//		ie. mprItoa(char *userBuf, int bufsize, int value);
//

char *mprItoa(int value, char *userBuf, int width)
{
	char	numBuf[16];
	char	*cp, *dp, *endp;
	int		negative;

	cp = &numBuf[sizeof(numBuf)];
	*--cp = '\0';

	if (value < 0) {
		negative = 1;
		value = -value;
		width--;
	} else {
		negative = 0;
	}

	do {
		*--cp = '0' + (value % 10);
		value /= 10;
	} while (value > 0);

	if (negative) {
		*--cp = '-';
	}

	dp = userBuf;
	endp = &userBuf[width];
	while (dp < endp && *cp) {
		*dp++ = *cp++;
	}
	*dp++ = '\0';
	return userBuf;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Make an argv array. Caller must free by calling mprFree(argv) to free
//	everything. The "program" and "cmd" must be static.
//

void mprMakeArgv(char *program, char *cmd, char ***argvp, int *argcp)
{
	char		*cp, **argv, *buf, *args;
	int			size, argc;

	//
	//	Allocate one buffer for argv and the actual args themselves
	//
	size = strlen(cmd) + 1;
	buf = (char*) mprMalloc((MPR_MAX_ARGC * sizeof(char*)) + size);
	args = &buf[MPR_MAX_ARGC * sizeof(char*)];
	strcpy(args, cmd);
	argv = (char**) buf;

	argc = 0;
	if (program) {
		argv[argc++] = program;
	}

	for (cp = args; cp && *cp != '\0'; argc++) {
		if (argc >= MPR_MAX_ARGC) {
			mprAssert(argc < MPR_MAX_ARGC);
			mprFree(buf);
			*argvp = 0;
			if (argcp) {
				*argcp = 0;
			}
			return;
		}
		while (isspace(*cp)) {
			cp++;
		}
		if (*cp == '\0')  {
			break;
		}
		if (*cp == '"') {
			cp++;
			argv[argc] = cp;
			while ((*cp != '\0') && (*cp != '"')) {
				cp++;
			}
		} else {
			argv[argc] = cp;
			while (*cp != '\0' && !isspace(*cp)) {
				cp++;
			}
		}
		if (*cp != '\0') {
			*cp++ = '\0';
		}
	}
	argv[argc] = 0;

	if (argcp) {
		*argcp = argc;
	}
	*argvp = argv;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Make intervening directories
//

int mprMakeDir(char *path)
{
	char	dir[MPR_MAX_PATH], buf[MPR_MAX_PATH];
	char	*dirSep;
	char	*next, *tok;

	dir[0] = '\0';
	dirSep = "/\\";

	if (path == 0 || *path == '\0') {
		return MPR_ERR_BAD_ARGS;
	}

	mprStrcpy(buf, sizeof(buf), path);
	next = mprStrTok(buf, dirSep, &tok);
	if (*buf == '/') {
		dir[0] = '/';
	}
	while (next != NULL) {
		if (strcmp(next, ".") == 0 ) {
			next = mprStrTok(NULL, dirSep, &tok);
			continue;
		}
		strcat(dir, next);
		if (access(dir, R_OK) != 0) {
			if (mkdir(dir, 0666) < 0) {
				return MPR_ERR_CANT_CREATE;
			}
		}
		strcat(dir, "/");
		next = mprStrTok(NULL, dirSep, &tok);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Get a fully qualified file name for the given path. Return with forward
//	slashes always
//

char *mprGetFullPathName(char *buf, int buflen, char *path)
{
#if (WIN || NW || OS2) && !BLD_FEATURE_ROMFS
	char	*junk, *cp;
	int	rc;

	--buflen;
	rc = GetFullPathName(path, buflen, buf, &junk);
	for (cp = buf; *cp; cp++) {
		if (*cp == '\\') {
			*cp = '/';
		}
	}
	buf[buflen] = '\0';
#else
	if (mprStrcpy(buf, buflen, path) < 0) {
		mprAssert(0);
		return 0;
	}
#endif
	return buf;
}

////////////////////////////////////////////////////////////////////////////////
#if BLD_FEATURE_MULTITHREAD

void mprLock()
{
	if (mpr) {
		mpr->lock();
	}
}

////////////////////////////////////////////////////////////////////////////////

void mprUnlock()
{
	if (mpr) {
		mpr->unlock();
	}
}

#endif

////////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
} // extern "C"
#endif

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// C++ Only /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//	Command line parsing class
//

MprCmdLine::MprCmdLine(int programArgc, char **programArgv, 
	char *programSwitches)
{
	optind = 1;
	optc = 0;
	argvBuf = 0;
	inSwitch = 0;
	argc = programArgc;
	argv = programArgv;
	switches = programSwitches;

#if WIN
	static char	arg0[MPR_MAX_FNAME];
	char		*cp;
	//
	//	Get the correct argv[0] program name
	//
	GetModuleFileName(0, arg0, sizeof(arg0));
	for (cp = arg0; *cp; cp++) {
		if (*cp == '\\') {
			*cp = '/';
		}
	}
	argv[0] = arg0;
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
//	Command line parsing class (suitable for windows). This constructor parses 
//	a single string converting words or quoted args into individual arguments. 
//	WARNING: modifies args
//

MprCmdLine::MprCmdLine(char *args, char *sw)
{
	optind = 1;
	optc = 0;
	switches = sw;
	argvBuf = 0;
	inSwitch = 0;

#if WIN
	static char	arg0[MPR_MAX_FNAME];
	char		*cp;
	//
	//	Get the correct argv[0] program name
	//
	GetModuleFileName(0, arg0, sizeof(arg0));
	for (cp = arg0; *cp; cp++) {
		if (*cp == '\\') {
			*cp = '/';
		}
	}
	mprMakeArgv(arg0, args, &argv, &argc);
#else
	mprMakeArgv(0, args, &argv, &argc);
#endif
	argvBuf = (char*) argv;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Destroy the clas
//

MprCmdLine::~MprCmdLine()
{
	if (argvBuf) {
		mprFree(argvBuf);
	}
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return next command line argument or switch. Return EOF when no more args
//	Very similar to getopt, next will return the switch parsed. If the switch
//	takes and argument, it will be returned in argp.
//

int MprCmdLine::next(char **argp)
{
	char	*ap;
	int		c;

	while (optind < argc) {
		c = argv[optind][optc];
		if (!inSwitch) {
			if (c == '-') {						// Leading switch char '-'
				optc++;
				inSwitch = 1;
				continue;
			} else {
				return EOF;
			}
		}
		if (c == '\0') {						// End of a word
			optind++;
			optc = 0;
			continue;
		}
		break;
	}
	if (!inSwitch || optind >= argc) {		// End of args
		return EOF;
	}

	c = argv[optind][optc++];
	if ((ap = strchr(switches, c)) == 0) {		// If not a valid switch
		return '?';								// End of switches
	}
	if (ap[1] == ':') {							// Switch takes an arg
		if ((optind + 1) >= argc) {
			return '?';
		}
		*argp = argv[++optind];
		optind++;
		optc = 0;
		inSwitch = 0;

	} else {									// Switch does not take an arg
		*argp = 0;
		if (argv[optind][optc] == '\0') {
			optind++;
			optc = 0;
			inSwitch = 0;
		}
	}
	return c;
}

////////////////////////////////////////////////////////////////////////////////
//
//	Return the next arg to use
//

int MprCmdLine::firstArg()
{
	return optind;
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
