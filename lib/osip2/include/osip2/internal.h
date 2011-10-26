/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003,2004  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include <osipparser2/osip_port.h>

#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#ifdef __BORLANDC__
#define _timeb timeb
#define _ftime ftime
#endif

#ifndef DOXYGEN

#if defined(WIN32) || defined(_WIN32_WCE)
/* Struct timeval */
struct timeval {
        long    tv_sec;         /* seconds */
        long    tv_usec;        /* and microseconds */
};
#endif

/**
 * Structure for payload management. Each payload element
 * represents one codec of a media line.
 * @var __payload_t
 */
typedef struct __payload __payload_t;

struct __payload
{
  char *payload;
  /*  char *port; this must be assigned by the application dynamicly */
  char *number_of_port;
  char *proto;
  char *c_nettype;
  char *c_addrtype;
  char *c_addr;
  char *c_addr_multicast_ttl;
  char *c_addr_multicast_int;
  /* rtpmap (rcvonly and other attributes are added dynamicly) */
  char *a_rtpmap;
};


/**
 * Allocate a payload element.
 * @param payload The payload.
 */
int __payload_init (__payload_t ** payload);
/**
 * Free a payload element.
 * @param payload The payload.
 */
void __payload_free (__payload_t * payload);


#ifdef OSIP_MT

/* Thread abstraction layer definition */

/* Is there any thread implementation available? */
/* HAVE_PTHREAD_H is not used any more! I keep it for a while... */
#if !defined(__VXWORKS_OS__) && !defined(__PSOS__) && \
	!defined(WIN32) && !defined(_WIN32_WCE) && !defined(HAVE_PTHREAD_WIN32) && \
    !defined(HAVE_PTHREAD) && !defined(HAVE_PTHREAD_H) && !defined(HAVE_PTH_PTHREAD_H)
#error No thread implementation found!
#endif

/* Pthreads support: */
/* - Unix: native Pthreads. */
/* - Win32: Pthreads for Win32 (http://sources.redhat.com/pthreads-win32). */
#if defined(HAVE_PTHREAD) || defined(HAVE_PTHREAD_H) || defined(HAVE_PTH_PTHREAD_H) || \
	defined(HAVE_PTHREAD_WIN32)
#include <pthread.h>
typedef pthread_t osip_thread_t;
#endif

/* Windows without Pthreads for Win32 */
#if (defined(WIN32) || defined(_WIN32_WCE)) && !defined(HAVE_PTHREAD_WIN32)
/* Prevent the inclusion of winsock.h */
#define _WINSOCKAPI_
#include <windows.h>
#undef _WINSOCKAPI_
typedef struct
{
  HANDLE h;
  unsigned id;
}
osip_thread_t;
#endif

#ifdef __VXWORKS_OS__
#include <taskLib.h>
typedef struct
{
  int id;
}
osip_thread_t;
#endif

#ifdef __PSOS__
#include <psos.h>
typedef struct
{
  unsigned long tid;
}
osip_thread_t;
#endif


/* Semaphore and Mutex abstraction layer definition */

/* Is there any semaphore implementation available? */
#if !defined(HAVE_SEMAPHORE_H) && !defined(HAVE_SYS_SEM_H) && \
    !defined(WIN32) && !defined(_WIN32_WCE) && !defined(HAVE_PTHREAD_WIN32) && \
    !defined(__PSOS__) && !defined(__VXWORKS_OS__)
#error No semaphore implementation found
#endif

/* Pthreads */
#if defined(HAVE_PTHREAD) || defined(HAVE_PTHREAD_H) || defined(HAVE_PTH_PTHREAD_H) || \
	defined(HAVE_PTHREAD_WIN32)
typedef pthread_mutex_t osip_mutex_t;
#endif

#ifdef __sun__
#include <semaphore.h>
#undef getdate
#include <synch.h>
#endif

#if (defined(HAVE_SEMAPHORE_H) && !defined(__APPLE_CC__)) || defined(HAVE_PTHREAD_WIN32)
#include <semaphore.h>
#ifdef __sun__
#undef getdate
#include <synch.h>
#endif
/**
 * Structure for referencing a semaphore element.
 * @var osip_sem_t
 */
typedef sem_t osip_sem_t;

#elif defined(HAVE_SYS_SEM_H)
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
typedef struct
{
  int semid;
}
osip_sem_t;
#endif

/* Windows without Pthreads for Win32 */
#if (defined(WIN32) || defined(_WIN32_WCE)) && !defined(HAVE_PTHREAD_WIN32)
/* Prevent the inclusion of winsock.h */
#define _WINSOCKAPI_
#include <windows.h>
#undef _WINSOCKAPI_
typedef struct
{
  HANDLE h;
}
osip_mutex_t;
typedef struct
{
  HANDLE h;
}
osip_sem_t;
#endif

#ifdef __VXWORKS_OS__
#include <semaphore.h>
#include <semLib.h>
typedef struct semaphore osip_mutex_t;
typedef sem_t osip_sem_t;
#endif

#ifdef __PSOS__
#include <Types.h>
#include <os.h>
typedef struct
{
  UInt32 id;
}
osip_mutex_t;
typedef struct
{
  UInt32 id;
}
osip_sem_t;
#endif


/* Condition variable abstraction layer definition */

/**
 * Structure for referencing a condition variable element.
 * @var osip_cond_t
 */
#if defined(HAVE_PTHREAD) || defined(HAVE_PTH_PTHREAD_H) || defined(HAVE_PTHREAD_WIN32)
typedef struct osip_cond
{
  pthread_cond_t cv;
} osip_cond_t;
#endif

#if (defined(WIN32) || defined(_WIN32_WCE)) && !defined(HAVE_PTHREAD_WIN32)
typedef struct osip_cond
{
  struct osip_mutex *mut;
  struct osip_sem *sem;
} osip_cond_t;
#endif

#if defined(__PSOS__) || defined(__VXWORKS_OS__)
typedef struct osip_cond
{
  struct osip_sem *sem;
} osip_cond_t;
#endif

#endif /* #ifdef OSIP_MT */

#endif /* #ifndef DOXYGEN */

#endif /* #ifndef _INTERNAL_H_ */
