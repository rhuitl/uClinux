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

#include <stdlib.h>
#include <stdio.h>

#include <osip2/internal.h>

#include <osip2/internal.h>
#include <osip2/osip_mt.h>


#if !defined(__VXWORKS_OS__) && !defined(__PSOS__) && \
	!defined(WIN32) && !defined(_WIN32_WCE) && !defined(HAVE_PTHREAD_WIN32) && \
    !defined(HAVE_PTHREAD) && !defined(HAVE_PTH_PTHREAD_H)
#error No thread implementation found!
#endif

#if defined(HAVE_PTHREAD) || defined(HAVE_PTH_PTHREAD_H) || defined(HAVE_PTHREAD_WIN32)

struct osip_mutex *
osip_mutex_init ()
{
  osip_mutex_t *mut = (osip_mutex_t *) osip_malloc (sizeof (osip_mutex_t));

  if (mut == NULL)
    return NULL;
  pthread_mutex_init (mut, NULL);
  return (struct osip_mutex *) mut;
}

void
osip_mutex_destroy (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return;
  pthread_mutex_destroy (mut);
  osip_free (mut);
}

int
osip_mutex_lock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return -1;
  return pthread_mutex_lock (mut);
}

int
osip_mutex_unlock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return -1;
  return pthread_mutex_unlock (mut);
}

#endif

#if (defined(HAVE_SEMAPHORE_H) && !defined(__APPLE_CC__)) || defined(HAVE_PTHREAD_WIN32)

/* Counting Semaphore is initialized to value */
struct osip_sem *
osip_sem_init (unsigned int value)
{
  osip_sem_t *sem = (osip_sem_t *) osip_malloc (sizeof (osip_sem_t));
  if (sem == NULL)
    return NULL;

  if (sem_init (sem, 0, value) == 0)
    return (struct osip_sem *) sem;
  osip_free (sem);
  return NULL;
}

int
osip_sem_destroy (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return 0;
  sem_destroy (sem);
  osip_free (sem);
  return 0;
}

int
osip_sem_post (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return sem_post (sem);
}

int
osip_sem_wait (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return sem_wait (sem);
}

int
osip_sem_trywait (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return sem_trywait (sem);
}

#elif defined (HAVE_SYS_SEM_H)
/* support for semctl, semop, semget */

#define SEM_PERM 0600

struct osip_sem *
osip_sem_init (unsigned int value)
{
  union semun val;
  int i;
  osip_sem_t *sem = (osip_sem_t *) osip_malloc (sizeof (osip_sem_t));

  if (sem == NULL)
    return NULL;

  sem->semid = semget (IPC_PRIVATE, 1, IPC_CREAT | SEM_PERM);
  if (sem->semid == -1)
    {
      perror ("semget error");
      osip_free (sem);
      return NULL;
    }
  val.val = (int) value;
  i = semctl (sem->semid, 0, SETVAL, val);
  if (i != 0)
    {
      perror ("semctl error");
      osip_free (sem);
      return NULL;
    }
  return (struct osip_sem *) sem;
}

int
osip_sem_destroy (struct osip_sem *_sem)
{
  union semun val;
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return 0;
  val.val = 0;
  semctl (sem->semid, 0, IPC_RMID, val);
  osip_free (sem);
  return 0;
}

int
osip_sem_post (struct osip_sem *_sem)
{
  struct sembuf sb;
  osip_sem_t *sem = (osip_sem_t *) _sem;

  if (sem == NULL)
    return -1;
  sb.sem_num = 0;
  sb.sem_op = 1;
  sb.sem_flg = 0;
  return semop (sem->semid, &sb, 1);
}

int
osip_sem_wait (struct osip_sem *_sem)
{
  struct sembuf sb;
  osip_sem_t *sem = (osip_sem_t *) _sem;

  if (sem == NULL)
    return -1;
  sb.sem_num = 0;
  sb.sem_op = -1;
  sb.sem_flg = 0;
  return semop (sem->semid, &sb, 1);
}

int
osip_sem_trywait (struct osip_sem *_sem)
{
  struct sembuf sb;
  osip_sem_t *sem = (osip_sem_t *) _sem;

  if (sem == NULL)
    return -1;
  sb.sem_num = 0;
  sb.sem_op = -1;
  sb.sem_flg = IPC_NOWAIT;
  return semop (sem->semid, &sb, 1);
}

#endif


/* use VxWorks implementation */
#ifdef __VXWORKS_OS__

struct osip_mutex *
osip_mutex_init ()
{
  return (struct osip_mutex *) semMCreate (SEM_Q_FIFO|SEM_DELETE_SAFE);
}

void
osip_mutex_destroy (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return;
  semDelete (mut);
}

int
osip_mutex_lock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return -1;
  return semTake (mut, WAIT_FOREVER);
}

int
osip_mutex_unlock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return -1;
  return semGive (mut);
}

struct osip_sem *
osip_sem_init (unsigned int value)
{
  SEM_ID initsem;
  osip_sem_t *x;

  x = (osip_sem_t *) osip_malloc (sizeof (osip_sem_t));
  if (x == NULL)
    return NULL;
  initsem = semCCreate (SEM_Q_FIFO, value);
  x->semId = initsem;
  x->refCnt = value;
  x->sem_name = NULL;
  return (struct osip_sem *) x;
}

int
osip_sem_destroy (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return 0;
  semDelete (sem->semId);
  osip_free (sem);
  return 0;
}

int
osip_sem_post (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return semGive (sem->semId);
}

int
osip_sem_wait (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return semTake (sem->semId, WAIT_FOREVER);
}

int
osip_sem_trywait (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return semTake (sem->semId, NO_WAIT);
}

#endif


#if (defined(WIN32) || defined(_WIN32_WCE)) && !defined(HAVE_PTHREAD_WIN32)

#include <limits.h>

struct osip_mutex *
osip_mutex_init ()
{
  osip_mutex_t *mut = (osip_mutex_t *) osip_malloc (sizeof (osip_mutex_t));
  if (mut == NULL)
    return NULL;
  if ((mut->h = CreateMutex (NULL, FALSE, NULL)) != NULL)
    return (struct osip_mutex *) (mut);
  osip_free (mut);
  return (NULL);
}

void
osip_mutex_destroy (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return;
  CloseHandle (mut->h);
  osip_free (mut);
}

int
osip_mutex_lock (struct osip_mutex *_mut)
{
  DWORD err;
  osip_mutex_t *mut = (osip_mutex_t *) _mut;

  if (mut == NULL)
    return -1;
  if ((err = WaitForSingleObject (mut->h, INFINITE)) == WAIT_OBJECT_0)
    return (0);
  return (EBUSY);
}

int
osip_mutex_unlock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut == NULL)
    return -1;
  ReleaseMutex (mut->h);
  return (0);
}

struct osip_sem *
osip_sem_init (unsigned int value)
{
  osip_sem_t *sem = (osip_sem_t *) osip_malloc (sizeof (osip_sem_t));
  if (sem == NULL)
    return NULL;

  if ((sem->h = CreateSemaphore (NULL, value, LONG_MAX, NULL)) != NULL)
    return (struct osip_sem *) (sem);
  osip_free (sem);
  return (NULL);
}

int
osip_sem_destroy (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return 0;
  CloseHandle (sem->h);
  osip_free (sem);
  return (0);
}

int
osip_sem_post (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  ReleaseSemaphore (sem->h, 1, NULL);
  return (0);
}

int
osip_sem_wait (struct osip_sem *_sem)
{
  DWORD err;
  osip_sem_t *sem = (osip_sem_t *) _sem;

  if (sem == NULL)
    return -1;
  if ((err = WaitForSingleObject (sem->h, INFINITE)) == WAIT_OBJECT_0)
    return (0);
  if (err == WAIT_TIMEOUT)
    return (EBUSY);
  return (EBUSY);
}

int
osip_sem_trywait (struct osip_sem *_sem)
{
  DWORD err;
  osip_sem_t *sem = (osip_sem_t *) _sem;

  if (sem == NULL)
    return -1;
  if ((err = WaitForSingleObject (sem->h, 0)) == WAIT_OBJECT_0)
    return (0);
  return (EBUSY);
}
#endif

#ifdef __PSOS__
struct osip_mutex *
osip_mutex_init ()
{
  osip_mutex_t *mut = (osip_mutex_t *) osip_malloc (sizeof (osip_mutex_t));

  if (sm_create ("mut", 1, 0, &mut->id) == 0)
    return (struct osip_mutex *) (mut);
  osip_free (mut);
  return (NULL);
}

void
osip_mutex_destroy (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut)
    {
      sm_delete (mut->id);
      osip_free (mut);
    }
}

int
osip_mutex_lock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut)
    {
      if (sm_p (mut->id, SM_WAIT, 0) != 0)
	return (-1);
    }
  return (0);
}

int
osip_mutex_unlock (struct osip_mutex *_mut)
{
  osip_mutex_t *mut = (osip_mutex_t *) _mut;
  if (mut)
    {
      sm_v (mut->id);
    }

  return (0);
}

struct osip_sem *
osip_sem_init (unsigned int value)
{
  osip_sem_t *sem = (osip_sem_t *) osip_malloc (sizeof (osip_sem_t));

  if (sm_create ("sem", value, 0, &sem->id) == 0)
    return (struct osip_sem *) (sem);
  osip_free (sem);
  return (NULL);
}

int
osip_sem_destroy (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return 0;
  sm_delete (sem->id);
  osip_free (sem);
  return (0);
}

int
osip_sem_post (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  return (sm_v (sem->id));
}

int
osip_sem_wait (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  if (sm_p (sem->id, SM_WAIT, 0) != 0)
    return (-1);
  return (0);
}

int
osip_sem_trywait (struct osip_sem *_sem)
{
  osip_sem_t *sem = (osip_sem_t *) _sem;
  if (sem == NULL)
    return -1;
  if (sm_p (sem->id, SM_NOWAIT, 0) != 0)
    return (-1);
  return (0);
}

#endif

#endif /* #ifdef OSIP_MT */
