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
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "camserv.h"
#include "socket.h"
#include "sockset.h"

/*
 * The sockset set provides a lot of convenient, common routines for 
 * accessing a group of file descriptors.  In a very common select() loop,
 * the return value from select() in addition to the overhead of managing
 * all of the descriptor sets can become cumbersome.  These routines allow
 * the programmer lots of freedom to expand their select() loop without
 * becoming too bogged down with file descriptor set information.
 *
 * The basic loop using the sockset utilities is:
 *
 * sockset_reset( socket_set );   // Resets all sockets which are 'active' 
 * sockset_select( .... );        // Same as a regular select
 *
 * set = sockset_query_socks( set ) // Returns set of all clientdatas for
 *                                  // sockets deemed 'active' by select
 * ... Manipulate stuff from set ...
 * free( set )
 *
 * -----------
 *
 * In addition to the basic socket handling procedures, another type
 * of useful routine is the 'hold' routines.  When a socket should be 
 * temporarily disabled from being processed by the select() routines, 
 * it can be put on 'hold'.  Later, all the sockets put on hold can come
 * off hold, and again be processed by select().  
 */

struct _sockset_st {
  fd_set active_fds;              /* FD's passed into and out of select() */
  fd_set preserve_fds;            /* FD's copied into active_fds */
  int nPreserve_fds;              /* Number of fds in preserve_fds */
  int preserve_arr[ FD_SETSIZE ]; /* Array from 0 < nPreserve_fds of each
				     fd currently in preserve_fds */
  /* Array of managed sockets.  Indexed to match preserve_arr */
  const Socket *managed_sockets[ FD_SETSIZE ]; 
  /* Array of clientdatas associated with sockets being managed.  
     Indexted to match managed_sockets */
  const void *managed_cldatas[ FD_SETSIZE ]; 

  /* Information about which file descriptors which are on 'hold' */
  struct {
    int nHeld;
    const Socket *held_sockets[ FD_SETSIZE ];
    const void *held_cldatas[ FD_SETSIZE ];
  } hold_info;
};

/*
 * sockset_new:  Create a new sockset structure, and initialize
 *               all the values.
 *
 * Return values:  Returns NULL on failure, else a valid pointer to
 *                 freshly malloced memory 
 */

SockSet *sockset_new(){
  SockSet *res;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  FD_ZERO( &res->active_fds );
  FD_ZERO( &res->preserve_fds );
  res->nPreserve_fds = 0;
  memset( res->preserve_arr, 0, sizeof( res->preserve_arr ));
  memset( res->managed_sockets, 0, sizeof( res->managed_sockets ));
  memset( res->managed_cldatas, 0, sizeof( res->managed_cldatas ));

  res->hold_info.nHeld = 0;
  memset( res->hold_info.held_sockets, 0, sizeof(res->hold_info.held_sockets));
  memset( res->hold_info.held_cldatas, 0, sizeof(res->hold_info.held_cldatas));
  return res;
}

/*
 * sockset_dest:  Destroy a sockset structure
 *
 * Arguments:     sset = Sockset structure to destroy
 */

void sockset_dest( SockSet *sset ){
  free( sset );
}

/*
 * sockset_hold:  Put a given socket on 'hold' 
 *
 * Arguments:     sset = Socket set containing the socket
 *                sock = Socket to be put on hold
 *
 * Return values: Returns -1 on failure, 0 on success
 */

int sockset_hold( SockSet *sset, const Socket *sock ){
  int i, sfd;

  sfd = socket_query_fd( sock );
  
  if( !FD_ISSET( sfd, &sset->preserve_fds ))
    return -1;

  for( i=0; i< sset->nPreserve_fds; i++ )
    if( sset->preserve_arr[ i ] == sfd )
      break;

  sset->hold_info.held_sockets[ sset->hold_info.nHeld ] = 
    sset->managed_sockets[ i ];
  sset->hold_info.held_cldatas[ sset->hold_info.nHeld ] = 
    sset->managed_cldatas[ i ];
  sset->hold_info.nHeld++;

  sockset_del_fd( sset, sock );
  return 0;
}

/*
 * sockset_unhold_all:   Return all sockets from their 'hold' state
 *                       to a normal state.
 *
 * Arguments:            sset = Socket set to change hold state infos of
 */

void sockset_unhold_all( SockSet *sset ){
  int i;

  for( i=0; i< sset->hold_info.nHeld; i++ ){
    sockset_add_fd( sset, 
		    sset->hold_info.held_sockets[ i ],
		    sset->hold_info.held_cldatas[ i ] );
  }
  sset->hold_info.nHeld = 0;
}


/*
 * sockset_query_socks:  (accessor function)  Retrieve an array
 *                       with socket_query_socks( sset ) elements, each
 *                       pointing to previously given cldata structures
 *                       which are currently in the active portion of the
 *                       socket set.
 *
 * Arguments:            sset = Sockset as returned from sockset_new()
 *
 * Return values:        Returns a malloced chunk of memory containing
 *                       information provided by the caller (cldata) for each
 *                       set socket.
 */

void **sockset_query_socks( const SockSet *sset ){
  const void **res;
  int i, j, nsocks;

  if( (nsocks = sockset_query_nsocks( sset )) == 0 )
    return NULL;

  if( (res = malloc( sizeof( *res ) * nsocks)) == NULL )
    return NULL;
  
  for( i=0, j=0; i< sset->nPreserve_fds; i++ ){
    if( FD_ISSET( sset->preserve_arr[ i ], &sset->active_fds ) )
      res[ j++ ] = sset->managed_cldatas[ i ];
  }

  return (void **)res;  /* Known cast to eliminate const problems */
}

/*
 * sockset_query_nsocks:  Query the number of sockets  in the
 *                        active set of a sockset
 *
 * Arguments:             sset = Sockset as returned from sockset_new()
 *
 * Return values:         Returns the # of active sockets.
 */

int sockset_query_nsocks( const SockSet *sset ){
  int i, res = 0;

  for( i=0; i< sset->nPreserve_fds; i++ )
    if( FD_ISSET( sset->preserve_arr[ i ], &sset->active_fds ))
      res++;

  return res;
}


/*
 * sockset_add_sock:  Add a socket to the socket's preserve list
 *                 
 * Arguments:         sset = Sockset as returned from sockset_new()
 *                    socket = Socket to add to the sockset.  Caller must
 *                             free the socket after sockset destroy.
 *
 * Return values:     Returns -1 on failure (too many FDs, or already set),
 *                    0 on success.a
 */

int sockset_add_fd( SockSet *sset, const Socket *new_sock, const void *cldata){
  int new_fd;

  new_fd = socket_query_fd( new_sock );
  
  if( sset->nPreserve_fds == FD_SETSIZE )
    return -1;
  
  if( FD_ISSET( new_fd, &sset->preserve_fds ) )
    return -1;

  sset->preserve_arr[ sset->nPreserve_fds ] = new_fd;
  sset->managed_sockets[ sset->nPreserve_fds] = new_sock;
  sset->managed_cldatas[ sset->nPreserve_fds] = cldata;

  sset->nPreserve_fds++;
  FD_SET( new_fd, &sset->preserve_fds );
  return 0;
}

/*
 * sockset_del_fd:  Delete a socket descriptor from the preserve set in a
 *                  sockset.  
 *
 * Arguments:       sset = Sockset as returned from sockset_new()
 *                  sock = Socket to delete from the sockset.  Caller must
 *                         free the socket.
 *
 * Return values:   Returns -1 if the sock was not contained in the sset, and
 *                  0 on success
 */

int sockset_del_fd( SockSet *sset, const Socket *sock ){
  int i, sfd;


  sfd = socket_query_fd( sock );

  if( !FD_ISSET( sfd, &sset->preserve_fds ))
    return -1;

  for( i=0; i< sset->nPreserve_fds; i++ ){
    if( sset->preserve_arr[ i ] == sfd )
      break;
  }

  sset->nPreserve_fds--;

  memmove( &sset->preserve_arr[ i ],
	   &sset->preserve_arr[ i + 1],
	   sizeof(sset->preserve_arr[ i ]) * (sset->nPreserve_fds - i ));
  memmove( &sset->managed_sockets[ i ],
	   &sset->managed_sockets[ i + 1],
	   sizeof(sset->managed_sockets[ i ]) * (sset->nPreserve_fds - i ));
  memmove( &sset->managed_cldatas[ i ],
	   &sset->managed_cldatas[ i + 1],
	   sizeof(sset->managed_cldatas[ i ]) * (sset->nPreserve_fds - i ));

  FD_CLR( sfd, &sset->preserve_fds );
  return 0;
}

/*
 * sockset_reset:  Copy the preserve file descriptors to the active
 *                 file descriptors.  This should be called before
 *                 any call to sockset_select()
 *
 * Arguments:      sset = Sockset as returned from sockset_new()
 */

void sockset_reset( SockSet *sset ){
  memcpy( &sset->active_fds, &sset->preserve_fds, sizeof( sset->preserve_fds));
}
  
/*
 * sockset_select:  Perform a traditional select on socksets.  See select()
 *                  for more information.
 *
 * Arguments:       highest_fd = see select(2)
 *                  readset    = Set of fd's to check for readability
 *                  writeset   = Set of fd's to check for writeability
 *                  tout       = see select(2)
 *
 * Return values:   see select(2)
 */

int sockset_select( int highest_fd, 
		    SockSet *readset, SockSet *writeset, struct timeval *tout )
{
  return select( highest_fd, 
		 &readset->active_fds,
		 &writeset->active_fds,
		 NULL,
		 tout );
}

    
  
