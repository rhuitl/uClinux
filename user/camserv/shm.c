/*  camserv - An internet streaming picture application
 *
 *  Copyright (C) 1999-2002  Jon Travis (jtravis@p00p.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>


#include "log.h"
#include "camshm.h"

#define MODNAME "shm"

/*
 * shm_dest:  Destroy a shared memory segment based on a shmid.
 *
 * Arguments:  shmid = Shared memory segment to destroy
 */

void shm_dest( int shmid ){
  if( shmctl( shmid, IPC_RMID, NULL ) == -1 ){
    camserv_log( MODNAME, "Unable to destroy shared memory segment");
    return;
  }
}

/*
 * shm_setup:  Setup a shared memory segment.
 *
 * Arguments:  pathname = Pathname to associated with shm segment.
 *             size     = # of bytes to allocate for shm
 *             addr     = Location to store pointer to new shared memory
 *
 * Return values:  Returns -1 if the shm segment could not be setup, else 0
 */

int shm_setup( const char *pathname, int size, char **addr ){
  key_t shm_key;
  int shm_res;
  pid_t pid;

  pid = getpid();

  if( (shm_key = ftok( pathname, pid )) == -1 ){
    camserv_log( MODNAME, "Failed to get shared memory key!");
    return -1;
  } 

  if( (shm_res = shmget( shm_key, size, 
			 IPC_CREAT | 0600 )) == -1 ){
    camserv_log( MODNAME, "Failed to create shared memory segment: %s",
		 strerror( errno ));
    return -1;
  }

  if( (*addr = shmat( shm_res, 0, 0 )) == NULL ){
    camserv_log( MODNAME, "Could not attach to shared memory segment: %s",
		 strerror( errno ));
    shm_dest( shm_res );
    return -1;
  }

  /* Now that we are attached, and everything is perfect, mark it for
     deletion, in case we exit abnormally */
  shm_dest( shm_res );
  return shm_res;
}


