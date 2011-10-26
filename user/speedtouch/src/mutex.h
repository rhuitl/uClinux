#ifndef MUTEX_H
#define MUTEX_H

/*
  Author: Benoit PAPILLAULT <benoit.papillault@free.fr>
  Creation: 01/06/2004

  Mutex library based on semaphore IPC
*/

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

/*
  Create a semaphore. Returns -1 on error.
*/
int mutex_init   (key_t key, int val);

/*
  Returns the current value of the second semaphore or -1 on errors
*/
int mutex_getval (int m_id);

/*
  Set the value of the second semaphore or -1 on errors
*/
int mutex_setval(int m_id, int val);

/*
  Try to lock the mutex. Either the mutex is locked and 0 is returned
  or the lock failed and -1 is returned.
*/

int mutex_trylock(int m_id);

/*
  Lock the mutex. If the mutex is already locked, the current process
  wait that it is unlocked
*/
int mutex_lock   (int m_id);

/*
  Unlock the mutex. This is done automatically when the process is
  killed
*/
int mutex_unlock (int m_id);

/*
  Destroy the mutex. All processes waiting for the mutex to be
  unlocked are awaken
*/
int mutex_done (int m_id);

#endif
