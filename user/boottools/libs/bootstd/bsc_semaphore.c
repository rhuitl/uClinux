/*
 * bsc_semaphore.c
 *
 * Copyright (c) 2006  Arcturus Networks Inc.
 *	by Oleksandr G Zhadan <www.ArcturusNetworks.com>
 *
 * All rights reserved.
 *
 * This material is proprietary to Arcturus Networks Inc. and, in
 * addition to the above mentioned Copyright, may be subject to
 * protection under other intellectual property regimes, including
 * patents, trade secrets, designs and/or trademarks.
 *
 * Any use of this material for any purpose, except with an express
 * license from Arcturus Networks Inc. is strictly prohibited.
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <bootstd.h>

#define BSC_SEM_MAGIC_KEY	0x42534353	/* "BSCS" */

union semun {
    int              val;    /* Value for SETVAL */
    struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
    unsigned short  *array;  /* Array for GETALL, SETALL */
    struct seminfo  *__buf;  /* Buffer for IPC_INFO
                                (Linux-specific) */
};

static int
bsc_sem_create (void)
{
    union semun semopts;
    int sid = semget(BSC_SEM_MAGIC_KEY, 1, IPC_CREAT|IPC_EXCL|0666);
    if	( sid != -1 ) {
        semopts.val = 1;
        semctl(sid, 0, SETVAL, semopts);
	}
    return sid;
}

int
bsc_sem_getval(int sid)
{
    int semval;
    semval = semctl(sid, 0, GETVAL, 0);
    return(semval);
}


int
bsc_sem_open(void)
{
    int sid = semget(BSC_SEM_MAGIC_KEY, 0, 0666);
    if  ( sid == -1 )
	sid = bsc_sem_create ();
    return sid;
}

int
bsc_sem_lock( int sid )
{
    struct sembuf sem_lock  = { 0, -1, 0 /* IPC_NOWAIT */ };
#if defined(SEMTIMEDOP)
    struct timespec timeout = { 3, 0 };
    semtimedop(sid, &sem_lock, 1, &timeout);
#else
    semop(sid, &sem_lock, 1);
#endif
    return 0;
}


void
bsc_sem_unlock( int sid )
{
    struct sembuf sem_unlock={ 0, 1, 0 /* IPC_NOWAIT*/ };
#if defined(SEMTIMEDOP)
    struct timespec timeout = { 3, 0 };
    semtimedop(sid, &sem_unlock, 1, &timeout);
#else
    semop(sid, &sem_unlock, 1);
#endif
}

void
bsc_sem_remove( int sid )
{
    semctl(sid, 0, IPC_RMID, 0);
}


void
bsc_sem_dispval( int sid )
{
    int semval;
    semval = semctl(sid, 0, GETVAL, 0);
    printf("BSC semval is %d\n", semval);
}
