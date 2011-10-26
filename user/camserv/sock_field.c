#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "camserv.h"
#include "sock_field.h"
#include "log.h"

#define MODNAME "sock_field"

#define MAX(x,y) (((x)<(y)) ? (y) : (x))

#define array_elem(x) (sizeof(x)/sizeof((x)[0]))

typedef struct sock_field_st {
  Socket *socket;                /* Socket connection                     */
  void *cldat;                   /* Clientdata associated with the socket */
  int valid;                     /* 1 if the sockfield is valid, else 0   */
} SockField;


struct sock_field_data {
  SockSet *readset, *writeset;     /* Read and writesets */
  int highest_fd;                  /* Highest FD managed */
  SockField clients[ FD_SETSIZE ]; /* All of the clients managed */
  Socket *listen_sock;             /* Listen sock of the field loop */
  SockField_ReadFunc   client_read;
  SockField_WriteFunc  client_write;
  SockField_AcceptFunc client_accept;
  SockField_PreCloseFunc client_preclose;
  void *sys_cldata;
  int shutdown;                    /* 1 if shutdown is requested, else 0  */
};

static
int sock_field_init_data( SockField_Data *sfdata ){
  int i;

  if( (sfdata->readset = sockset_new()) == NULL ){
    camserv_log( MODNAME, "Error setting up readset!" );
    return -1;
  } 
  if( (sfdata->writeset = sockset_new()) == NULL ){
    camserv_log( MODNAME, "Error setting up writeset!" );
    return -1;
  }

  sfdata->highest_fd = -1;
  sfdata->listen_sock = NULL;
  for( i=0; i< array_elem( sfdata->clients ); i++ ){
    sfdata->clients[ i ].socket = NULL;
    sfdata->clients[ i ].cldat  = NULL;
    sfdata->clients[ i ].valid  = 0;
  }

  sfdata->client_write = NULL;
  sfdata->client_read  = NULL;
  sfdata->client_accept = NULL;
  sfdata->client_preclose = NULL;
  return 0;
}
  
static
void sock_field_dest_data( SockField_Data *sfdata ){
  sockset_dest( sfdata->readset );
  sockset_dest( sfdata->writeset );
}


int sock_field_manage_socket( SockField_Data *sfdata, 
			      Socket *sock, void *cldat )
{
  int i;

  if( !sfdata || !sock ) 
    camserv_log( MODNAME, "manage_socket argument failure!" );

  /* Find an unused socket entry */
  for( i=0; i< array_elem( sfdata->clients ); i++ )
    if( sfdata->clients[ i ].valid == 0) 
      break;

  if( i == array_elem( sfdata->clients )) {
    /* Didn't find an available slot! */
    return -1;
  }

  if( sockset_add_fd( sfdata->readset, sock, &sfdata->clients[ i ] ) == -1 ){
    camserv_log( MODNAME,  "Error adding socket to readset!" );
    return -1;
  }

  if( sockset_add_fd( sfdata->writeset, sock, &sfdata->clients[ i ] ) == -1 ){
    camserv_log( MODNAME, "Error adding socket to writeset!" );
    sockset_del_fd( sfdata->readset, sock );
    return -1;
  }

  sfdata->clients[ i ].socket = sock;
  sfdata->clients[ i ].cldat  = cldat;
  sfdata->clients[ i ].valid  = 1;
  sfdata->highest_fd = MAX( sfdata->highest_fd, socket_query_fd( sock ) );
  return 0;
}

static
int sock_field_service_writesocks( SockField_Data *sfdata ){
  void **set_socks;
  int nsocks, i, res;
  SockField *sfield;

  if( !(nsocks = sockset_query_nsocks( sfdata->writeset )))
    return 0;

  if( (set_socks = sockset_query_socks( sfdata->writeset )) == NULL ){
    camserv_log( MODNAME, "Couldn't query active writesocket data!" );
    return -1;
  }

  for( i=0; i< nsocks; i++ ){
    sfield = set_socks[ i ] ;
    res = sfdata->client_write( sfdata, sfield->socket, sfield->cldat );
    if( res & SOCKFIELD_SHUTDOWN ) {
      camserv_log( MODNAME, "Shutdown requested" );
      sfdata->shutdown = 1;
    }
    if( res & SOCKFIELD_CLOSE ) {
      /* Requested a close */
      sfdata->client_preclose( sfield->socket, sfield->cldat, 
			       sfdata->sys_cldata );
      sockset_del_fd( sfdata->readset, sfield->socket );
      sockset_unhold_all( sfdata->writeset );
      sockset_del_fd( sfdata->writeset, sfield->socket );
      socket_dest( sfield->socket );
      sfield->valid = 0;
      camserv_log( MODNAME, "Closed socket" );
    }
  }    
  free( set_socks );
  return 0;
}

static
int sock_field_service_readsocks( SockField_Data *sfdata ){
  void **set_socks;
  int nsocks, i;
  SockField *sfield;

  if( !(nsocks = sockset_query_nsocks( sfdata->readset )))
    return 0;

  if( (set_socks = sockset_query_socks( sfdata->readset )) == NULL ){
    camserv_log( MODNAME, "Couldn't query active readsocket data!" );
    return -1;
  }

  for( i=0; i< nsocks; i++ ){
    sfield = set_socks[ i ] ;
    if( sfield == NULL ){  /* Listen sock is the only NULL clientinfo */
      sfdata->client_accept( sfdata, sfdata->listen_sock, sfdata->sys_cldata );
      continue;
    } else {
      int res;

      res = sfdata->client_read( sfdata, sfield->socket, sfield->cldat );
      if( res & SOCKFIELD_SHUTDOWN ){
	camserv_log( MODNAME, "Shutdown requested" );
	sfdata->shutdown = 1;
      }

      if( res & SOCKFIELD_CLOSE )
      {
	sfdata->client_preclose( sfield->socket, sfield->cldat, 
				 sfdata->sys_cldata );
	/* Requested a close */
	sockset_del_fd( sfdata->readset, sfield->socket );
	sockset_unhold_all( sfdata->writeset );
	sockset_del_fd( sfdata->writeset, sfield->socket );
	socket_dest( sfield->socket );
	sfield->valid = 0;
      }
    }
  }
  free( set_socks );
  return 0;
}

void sock_field_unhold_write( SockField_Data *sfdata ){
  sockset_unhold_all( sfdata->writeset );
}

void sock_field_hold_write( SockField_Data *sfdata, Socket *socket ) {
  if( sockset_hold( sfdata->writeset, socket ) == -1 ){
    camserv_log( MODNAME, "Failed to hold write!" );
  }
}

int sock_field( Socket *listen_sock,
		void *sys_cldata,
		SockField_InitFunc init_func,
		SockField_AcceptFunc accept_func,
		SockField_ReadFunc read_func,
		SockField_WriteFunc write_func,
		SockField_PreCloseFunc preclose_func,
		SockField_TimeoutFunc  timeout_func,
		struct timeval *timeout ) 
{
  extern int errno;
  SockField_Data sfdata;
  int i;
  struct timeval real_timeout;

  if( sock_field_init_data( &sfdata ) == -1 )
    return -1;

  sfdata.highest_fd      = socket_query_fd( listen_sock );
  sfdata.listen_sock     = listen_sock;
  sfdata.client_read     = read_func;
  sfdata.client_write    = write_func;
  sfdata.client_accept   = accept_func;
  sfdata.client_preclose = preclose_func;
  sfdata.sys_cldata      = sys_cldata;
  sfdata.shutdown        = 0;

  if( init_func( &sfdata, sys_cldata ) == -1 ){
    sock_field_dest_data( &sfdata );
    return -1;
  }

  if( sockset_add_fd( sfdata.readset, listen_sock, NULL ) == -1 ){
    camserv_log( MODNAME, "Error adding listen sock to readset!" );
    sock_field_dest_data( &sfdata );
    return -1;
  }

  /* Do stuff */
  while( sfdata.shutdown == 0 ) {
    int sockres;

    sockset_reset( sfdata.readset );
    sockset_reset( sfdata.writeset );
    real_timeout = *timeout;
    sockres = sockset_select( sfdata.highest_fd + 1, sfdata.readset,
			      sfdata.writeset, &real_timeout );
    if( sockres < 0 && errno != EINTR ) {
      camserv_log( MODNAME, "Select failure: \"%s\"", strerror( errno ));
      break;
    }

    if( sockres == 0 ){
      timeout_func( &sfdata, sys_cldata );
    }

    if( sock_field_service_readsocks( &sfdata ) == -1 )
      break;
    if( sock_field_service_writesocks( &sfdata ) == -1 )
      break;
  }

  /* Closing time */
  
  sockset_unhold_all( sfdata.writeset );
  for( i=0; i< array_elem( sfdata.clients ); i++ ){
    if( !sfdata.clients[ i ].valid ) continue;
    preclose_func( sfdata.clients[ i ].socket, sfdata.clients[ i ].cldat,
		   sfdata.sys_cldata );
    socket_dest( sfdata.clients[ i ].socket );
    sfdata.clients[ i ].valid = 0;
  }
  sock_field_dest_data( &sfdata );
  return 0;
}
