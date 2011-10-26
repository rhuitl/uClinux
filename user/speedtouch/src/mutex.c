#include "mutex.h"
#include <errno.h>

#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
    int val;                    /* value for SETVAL */
    struct semid_ds *buf;       /* buffer for IPC_STAT, IPC_SET */
    unsigned short int *array;  /* array for GETALL, SETALL */
    struct seminfo *__buf;      /* buffer for IPC_INFO */
};
#endif

int semaphore_init(key_t key, int val1, int val2)
{
    int semid;
    union semun un;

    for (;;)
    {
        semid = semget(key, 2, IPC_CREAT | IPC_EXCL | 0666);
        if (semid < 0)
        {
            if (errno != EEXIST)
                return semid;

            /* the semaphore set already exists */

            semid = semget(key, 2, 0666);
            if (semid < 0)
            {
                if (errno != ENOENT)
                    return semid;
                /* the semaphore set has been destroyed before we get
                 * access. So we try again to create it */
            }
            else
            {
                /* semaphore creation OK. value is already initialized */
                return semid;
            }
        }
        else
        {
            /* we need to initialize the value */

            unsigned short array [2];

            array[0] = val1;
            array[1] = val2;

            un.array = array;

            if (semctl(semid, 0, SETALL, un) < 0)
                return -1;

            return semid;
        }
    }
}

int semaphore_incr(int semid, int count)
{
    struct sembuf sbuf;

    sbuf.sem_num  = 0;
    sbuf.sem_op   = count;
    sbuf.sem_flg = SEM_UNDO;

    return semop(semid, &sbuf, 1);
}

int semaphore_decr(int semid, int count)
{
    struct sembuf sbuf;

    sbuf.sem_num  = 0;
    sbuf.sem_op   = -count;
    sbuf.sem_flg = SEM_UNDO;

    return semop(semid, &sbuf, 1);
}

int semaphore_trydecr(int semid, int count)
{
    struct sembuf sbuf;

    sbuf.sem_num  = 0;
    sbuf.sem_op   = -count;
    sbuf.sem_flg = SEM_UNDO | IPC_NOWAIT;

    return semop(semid, &sbuf, 1);
}

int semaphore_done(int semid)
{
    union semun un;

    return semctl(semid, 0, IPC_RMID, un);
}

int mutex_init(key_t key, int val)
{
    return semaphore_init(key, 1, val);
}

int mutex_getval(int m_id)
{
    return semctl(m_id, 1, GETVAL, 0);
}

int mutex_setval(int m_id, int val)
{
    union semun un;

    un.val = val;
    return semctl(m_id, 1, SETVAL, un);
}

int mutex_trylock(int m_id)
{
    return semaphore_trydecr(m_id, 1);
}

int mutex_lock(int m_id)
{
    return semaphore_decr(m_id, 1);
}

int mutex_unlock(int m_id)
{
    return semaphore_incr(m_id, 1);
}

int mutex_onde(int m_id)
{
    return semaphore_done(m_id);
}
