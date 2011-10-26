/**
 * @file   common_defs.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 20 15:47:49 2003
 * 
 * @brief  common include stuff I use all the time
 * 
 * 
 */

#ifndef _COMMON_DEFS_H
#define _COMMON_DEFS_H

#ifndef DEBUG
    #ifndef INLINE
        #define INLINE inline
    #endif

    #define FLOWASSERT(a)  
#else
    #ifdef INLINE
        #undef INLINE
    #endif
    #define INLINE
    #include <assert.h>
    #define FLOWASSERT(a) assert(a)
#endif /* DEBUG */

#define ONE_MBYTE (1024 * 1024)
#define ONE_HOUR  3600

#define FULLBITS 0xFFFFFFFF

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

#ifndef WIN32
/* for inet_ntoa */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#endif /* _COMMON_DEFS_H */
