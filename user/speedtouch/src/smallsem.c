/*
*  Little semaphore/mutex helper library for the ALCATEL SpeedTouch 
*  USB driver
*
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
*  Author : Benoit LOCHER <benoit.locher@skf.com>
*
*  History:
*
*  Date        Author             Comment
*  23/07/2001  Benoit LOCHER      Initial release
*
*
*
* Summary of functions
*
*  int sem_create(key_t)          creation of a semaphore (IPC wise), must already exist
*  int sem_get(key_t)             retrieve an existing semaphore
*  int sem_init(int, int)         initialise a semaphore with a known value
*  int sem_P(int)                 "P" operation on the semaphore (grab the resource)
*  int sem_V(int)                 "V" operation on the semaphore (release the resource)
*  int sem_destroy(int)           destroys the semaphore from the system
*
*  $Id: smallsem.c,v 1.2 2001/11/07 19:45:26 edgomez Exp $
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "smallsem.h"



int sem_create(key_t key)
{
	int	sem;

	if ((sem=semget(key, 1, IPC_CREAT|IPC_EXCL|0755))==-1)
	{
		return -1;
	}
	return sem;
}


int sem_init(int sem, int res_cnt)
{
	union semun su;

	su.val=res_cnt;
	if (semctl(sem, 0, SETVAL, su)==-1)
		return -1;
	return 0;
}


int sem_get(key_t key)
{
	int     sem;

	if ((sem=semget(key, 1, 0755))==-1)
	{
		return -1;
	}
	return sem;
}


int sem_destroy(int sem)
{
	if (semctl(sem, 0, IPC_RMID, 0)==-1)
	{
		return -1;
	}
	return 0;
}


int sem_P(int sem)
{
	struct sembuf sb;

	sb.sem_num=0;
	sb.sem_op=-1;
	sb.sem_flg=0;
	if (semop(sem, &sb, 1)==-1)
	{
		return -1;
	}
	return 0;
}


int sem_V(int sem)
{
	struct sembuf sb;

	sb.sem_num=0;
	sb.sem_op=1;
	sb.sem_flg=0;
	if (semop(sem, &sb, 1)==-1)
	{
		return -1;
	}
	return 0;
}

