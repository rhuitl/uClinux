/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003  Aymeric MOIZARD jack@atosc.org
  
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

#ifdef OSIP_MT

#include <stdio.h>

#include <osip2/internal.h>
#include <osip2/osip_mt.h>

#if (defined(WIN32) || defined(_WIN32_WCE)) && !defined(HAVE_PTHREAD_WIN32)
#  if defined _WIN32_WCE
#    include <winbase.h>
#    define _beginthreadex	CreateThread
#    define	_endthreadex	ExitThread
#  elif defined WIN32
#    include <process.h>
#  endif
#endif

/* stack size is only needed on VxWorks. */

#ifndef __VXWORKS_OS__
#if defined(HAVE_PTHREAD) || defined(HAVE_PTH_PTHREAD_H) || defined(HAVE_PTHREAD_WIN32)

struct osip_thread *
osip_thread_create (int stacksize, void *(*func) (void *), void *arg)
{
  int i;
  osip_thread_t *thread =
    (osip_thread_t *) osip_malloc (sizeof (osip_thread_t));
  if (thread == NULL)
    return NULL;

  i = pthread_create (thread, NULL, func, (void *) arg);
  if (i != 0)
    {
      OSIP_TRACE (osip_trace
		  (__FILE__, __LINE__, OSIP_ERROR, NULL,
		   "Error while creating a new thread\n"));
      return NULL;
    }
  return (struct osip_thread *) thread;
}

int
osip_thread_set_priority (struct osip_thread *thread, int priority)
{
  return 0;
}

int
osip_thread_join (struct osip_thread *_thread)
{
  osip_thread_t *thread = (osip_thread_t *) _thread;
  if (thread == NULL)
    return -1;
  return pthread_join (*thread, NULL);
}

void
osip_thread_exit ()
{
  pthread_exit (NULL);
}

#endif
#endif


#if (defined(WIN32) || defined(_WIN32_WCE)) && !defined(HAVE_PTHREAD_WIN32)

struct osip_thread *
osip_thread_create (int stacksize, void *(*func) (void *), void *arg)
{
  osip_thread_t *thread =
    (osip_thread_t *) osip_malloc (sizeof (osip_thread_t));
  if (thread == NULL)
    return NULL;
  thread->h = (HANDLE) _beginthreadex (NULL,	/* default security attr */
				       0,	/* use default one */
				      (unsigned (__stdcall *)(void *)) func, arg, 0, &(thread->id));
  if (thread->h == 0)
    {
      osip_free (thread);
      return NULL;
    }
  return (struct osip_thread *) thread;
}

int
osip_thread_join (struct osip_thread *_thread)
{
  int i;
  osip_thread_t *thread = (osip_thread_t *) _thread;

  if (thread == NULL)
    return -1;
  i = WaitForSingleObject (thread->h, INFINITE);
  if (i == WAIT_OBJECT_0)
    {
      /* fprintf (stdout, "thread joined!\n"); */
    }
  else
    {
      /* fprintf (stdout, "ERROR!! thread joined ERROR!!\n"); */
      return -1;
    }
  CloseHandle (thread->h);
  return (0);
}

void
osip_thread_exit ()
{
  /* ExitThread(0); */
  _endthreadex (0);
}

int
osip_thread_set_priority (struct osip_thread *thread, int priority)
{
  return 0;
}


#endif

#ifndef __VXWORKS_OS__
#ifdef __PSOS__
struct osip_thread *
osip_thread_create (int stacksize, void *(*func) (void *), void *arg)
{
  osip_thread_t *thread =
    (osip_thread_t *) osip_malloc (sizeof (osip_thread_t));
  if (thread == NULL)
    return (NULL);
  if (t_create ("sip", 150, stacksize, 0, 0, &thread->tid) != 0)
    {
      osip_free (thread);
      return (NULL);
    }

  if (t_start (thread->tid, T_PREEMPT | T_ISR, func, 0) != 0)
    {
      osip_free (thread);
      return (NULL);
    }

  return (struct osip_thread *) thread;
}

int
osip_thread_set_priority (struct osip_thread *_thread, int priority)
{
  unsigned long oldprio;
  osip_thread_t *thread = (osip_thread_t *) _thread;

  if (thread == NULL)
    return -1;
  t_set_pri (thread->tid, priority, &oldprio);
  return 0;
}

int
osip_thread_join (struct osip_thread *_thread)
{
  osip_thread_t *thread = (osip_thread_t *) _thread;
  if (thread == NULL)
    return -1;
  t_delete (thread->tid);

  return (0);
}

void
osip_thread_exit ()
{
  t_delete (0);
}
#endif
#endif

#ifdef __VXWORKS_OS__
struct osip_thread *
osip_thread_create (int stacksize, void *(*func) (void *), void *arg)
{
  osip_thread_t *thread =
    (osip_thread_t *) osip_malloc (sizeof (osip_thread_t));
  if (thread == NULL)
    return NULL;
  thread->id = taskSpawn (NULL, 5, 0, stacksize, (FUNCPTR) func, (int) arg,
			  0, 0, 0, 0, 0, 0, 0, 0, 0);
  if (thread->id < 0)
    osip_free (thread);
  return (struct osip_thread *) thread;
}

int
osip_thread_set_priority (struct osip_thread *_thread, int priority)
{
  osip_thread_t *thread = (osip_thread_t *) _thread;
  if (thread == NULL)
    return -1;
  taskPrioritySet (thread->id, 1);
  return 0;
}

int
osip_thread_join (struct osip_thread *_thread)
{
  osip_thread_t *thread = (osip_thread_t *) _thread;
  if (thread == NULL)
    return -1;
  return taskDelete (thread->id);
}

void
osip_thread_exit ()
{
  /*?? */
}

#endif

#endif /* #ifdef OSIP_MT */
