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
#include <sys/unistd.h>
#include <fcntl.h>

#include "socket.h"

#define BAD_SOCKET -1
#define BAD_PORT   -1
#define MAX_SOCKET_REMOTE_NAME 512

struct socket_st {
  int fd;
  char remote_name[ MAX_SOCKET_REMOTE_NAME ];     /* hostname of remote */
  short port;
};

/*
 * socket_zero:  Zero out a socket structure
 *
 * Arguments:    sock = Socket to zero out
 */
 
void socket_zero( Socket *sock ){
  sock->fd = BAD_SOCKET;
  sock->port = BAD_PORT;
  strcpy( sock->remote_name, "** Disconnected **" );
}

/*
 * socket_new:  Create a new socket structure and initialize it
 *
 * Return values:  Returns NULL on failure, else a valid pointer to a new 
 *                 socket.
 */

Socket *socket_new(){
  Socket *res;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  socket_zero( res );
  return res;
}

/*
 * socket_dest:  Destroy a previously allocated socket
 * 
 * Arguments:    sock = socket to destroy
 */

void socket_dest( Socket *sock ){
  if( sock->fd >= 0 )
    close( sock->fd );
  free( sock );
}


/*
 * socket_query_remote_name:  Get the remote IP address connected to the sock
 *
 * Arguments:                 sock = Socket to get the remote IP of
 *
 * Return values:             Returns the remote name
 */

const char *socket_query_remote_name( Socket *sock ){
  return sock->remote_name;
}

/*
 * socket_query_fd:  Get the FD associated with a socket
 *                      
 * Arguments:        sock = Socket to get the FD of
 * 
 * Return values:    Returns the FD of the sock, or -1 if the fd is invalid.
 */
       
int socket_query_fd( const Socket *sock ){
  return sock->fd;
}

/*
 * socket_set_remote_name:  Set the remote name of a socket
 *
 * Arguments:               sock = Socket to set the name of
 *                          new_name = New name for the socket
 */

static
void socket_set_remote_name( Socket *sock, const char *new_name ){
  strncpy( sock->remote_name, new_name, sizeof( sock->remote_name ) -1 );
  sock->remote_name[ sizeof( sock->remote_name ) - 1 ] = '\0';
}

/*
 * socket_resolv_hostname:  Resolve a string hostname to a internet sockaddr
 *                          structure
 *
 * Arguments:               hname = Hostname to resolve.
 *                          sin   = Sockaddr struct to place resolved host
 *
 * Return values:           Returns -1 on failure, 0 on succes.
 */

static
int socket_resolv_hostname( const char *hname, struct sockaddr_in *sin ){
  struct hostent *hostp;
  unsigned long addr;

  addr = inet_addr( hname );
#ifdef INADDR_NONE
  if( addr != INADDR_NONE )
    memcpy( &sin->sin_addr, &addr, sizeof( addr ));
#else
  if (addr != (in_addr_t)-1)
    memcpy( &sin->sin_addr, &addr, sizeof( addr ));
#endif
  else {
    hostp = gethostbyname( hname );
    if( hostp == NULL )
      return -1;
    else
      memcpy( &sin->sin_addr, hostp->h_addr, hostp->h_length );
  }

  return 0;
}

/*
 * socket_unix_pair_dest:  Destroy a previously created socket pair
 *
 * Arguments:              sockpar = Sockpair to destroy
 */

void socket_unix_pair_dest( Socket **sockpair ){
  socket_dest( sockpair[ 0 ] );
  socket_dest( sockpair[ 1 ] );
  free( sockpair );
}

/*
 * socket_unix_pair:  Create a UNIX socket pair
 */

Socket **socket_unix_pair( int type ){
  Socket **res;
  int resfd[2];

  if( (res = malloc( sizeof( *res ) * 2 )) == NULL )
    return NULL;
  
  if( (res[ 0 ] = socket_new()) == NULL ||
      (res[ 1 ] = socket_new()) == NULL )
    return NULL;

  if( socketpair( PF_UNIX, type, 0, resfd ) == -1 ) {
    socket_dest( res[ 0 ] );
    socket_dest( res[ 1 ] );
    free( res );
    return NULL;
  }

  socket_set_remote_name( res[ 0 ], "Local Unix Socket" );
  socket_set_remote_name( res[ 1 ], "Local Unix Socket" );

  res[ 0 ]->fd = resfd[ 0 ];
  res[ 1 ]->fd = resfd[ 1 ];

  return res;
}

/*
 * socket_serve_tcp:  Createa new socket which serves as a listening socket.
 *
 * Arguments:         hname = hostname to bind to.  One can bind to only
 *                            listening to a certain address, or NULL can be
 *                            passed in to listen to all addys
 *                    port  = Port number to listen on
 *                    backlog = Backlog arg to listen()
 *
 * Return values:     Returns NULL on failure, else a valid listen sock on 
 *                    success
 */

Socket *socket_serve_tcp( const char *hname, int port, int backlog ){
  Socket *sockres;
  struct sockaddr_in sin;
  int val;

  if( (sockres = socket_new()) == NULL )
    return NULL;

  sockres->port = port;

  if( (sockres->fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP )) < 0 ){
    perror( "socket()" );
    socket_dest( sockres );
    return NULL;
  }

  sin.sin_family = AF_INET;
  sin.sin_port   = htons( port );
  
  if( hname == NULL ) {
    sin.sin_addr.s_addr = INADDR_ANY;
    socket_set_remote_name( sockres, "Any Host" );
  } else {
    socket_set_remote_name( sockres, hname );
    if( socket_resolv_hostname( hname, &sin ) == -1 ) {
      socket_dest( sockres );
      return NULL;
    }
  }

  val = 1;
  if( setsockopt( sockres->fd,SOL_SOCKET,SO_REUSEADDR, &val, sizeof( int )) <0)
    perror( "setsockopt()" );
  val = 1;
  if( setsockopt( sockres->fd,SOL_SOCKET,SO_KEEPALIVE, &val, sizeof( int )) <0)
    perror( "setsockopt()" );

  if( bind( sockres->fd, (struct sockaddr *)&sin, sizeof( sin )) < 0 ) {
    perror( "bind()" );
    socket_dest( sockres );
    return NULL;
  }

  if( listen( sockres->fd, backlog ) < 0 ) {
    perror( "close()" );
    socket_dest( sockres );
    return NULL;
  }

  return sockres;
}

/*
 * socket_access:  Accept a connection on a listen sock, and create a new
 *                 socket for the new connection.
 *
 * Arguments:      listen_sock = Listen sock as setup by socket_serve_tcp
 *
 * Return values:  Returns a new socket representing the new connection on
 *                 success, and NULL on failure.
 */

Socket *socket_accept( const Socket *listen_sock ){
  Socket *new_socket;
  struct sockaddr saddr;
  struct sockaddr_in *sin;
  unsigned int addrlen = sizeof( saddr );
  int accres;

  if( (accres = accept( listen_sock->fd, &saddr, &addrlen )) == -1 )
    return NULL;

  if( (new_socket = socket_new()) == NULL )
    return NULL;

  sin = (struct sockaddr_in *)&saddr;

  new_socket->fd = accres;
  new_socket->port = sin->sin_port;
  socket_set_remote_name( new_socket, inet_ntoa( sin->sin_addr ));
  return new_socket;
}


/*
 * socket_connect:  Connect to a remote socket, and return a new connection
 *                  object.
 *
 * Arguments:       remote_name = Remote hostname to connect to
 *                  remote_port = Remote port to connect to
 *
 * Return values:   Returns NULL on failure, else a valid pointer to a new
 *                  socket structure.
 */

Socket *socket_connect( const char *remote_name, int remote_port ){
  Socket *res;
  struct sockaddr_in sin;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  res->port = remote_port;

  if( (res->fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP )) < 0 ){
    perror( "socket()" );
    socket_dest( res );
    return NULL;
  }

  sin.sin_family = AF_INET;
  sin.sin_port   = htons( remote_port );

  if( socket_resolv_hostname( remote_name, &sin ) == -1 ){
    socket_dest( res );
    return NULL;
  }

  if( connect( res->fd, (struct sockaddr *)&sin, sizeof( sin )) == -1 ){
    perror( "connect()" );
    socket_dest( res );
    return NULL;
  }

  socket_set_remote_name( res, remote_name );
  return res;
}

int socket_set_nonblock( Socket *sock ){
  if( fcntl( socket_query_fd( sock ), F_SETFL, O_NONBLOCK ) == -1)
    return -1;
  else
    return 0;
}
