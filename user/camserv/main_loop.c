#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>

#include "camserv.h"
#include "camconfig.h"
#include "socket.h"
#include "mainloop.h"
#include "sockset.h"
#include "manager.h"
#include "databuf.h"
#include "list.h"
#include "log.h"

extern int errno;

static int Abort = 0;

#define CINFO_STATE_PREAMBLE    0
#define CINFO_STATE_PICTURE     1
#define CINFO_STATE_SEPERATOR   2
#define CINFO_STATE_SENDSIZE    3
#define CINFO_STATE_UNINIT      4

#define CLIENT_T_PROXY          0
#define CLIENT_T_BROWSER        1
#define CLIENT_T_UNINIT         2
#define CLIENT_T_SINGLE         3

#define RANDOMSTRING "ThisRandomString"
#define CONTENTTYPE  "image/jpeg"

#define MODNAME "mainloop"

#define MAX(x,y) (((x)>(y)) ? (x) : (y))

typedef struct client_info_st {
  Socket *socket;           
  DataBuf *writebuf;
  void *management_data;
  int state;                    /* One of CINFO_STATE_* */

  time_t create_time;           /* Resource management */
  unsigned int bytes;
  unsigned int frames;

  unsigned int max_seconds;              /* Max resource info */
  unsigned int max_bytes;
  unsigned int max_frames;

  /********** Proxy only *********/
  unsigned long proxypic_size;  /* network order size of picture to send */
  char *proxypic_data;
  /*******************************/

  int last_picture_id;
  int client_type;              /* One of CLIENT_T_*    */
} ClientInfo;

static
char *get_multi_preamble_text( size_t *len){
#define MPREAMBLE_STR "HTTP/1.0 200 OK\n"  \
  "Content-type: multipart/x-mixed-replace;boundary=" RANDOMSTRING "\n" \
  "Cache-Control: no-cache\n" \
  "Cache-Control: private\n" \
  "Pragma: no-cache\n\n" \
  "--" RANDOMSTRING "\n" \
  "Content-type: " CONTENTTYPE "\n\n"
  
  if( len != NULL ) *len = sizeof( MPREAMBLE_STR ) - 1;
  return MPREAMBLE_STR;
}

static
char *get_single_preamble_text( size_t *len){
#define SPREAMBLE_STR "HTTP/1.0 200 OK\n"  \
  "Content-type: " CONTENTTYPE "\n" \
  "Cache-Control: no-cache\n" \
  "Cache-Control: private\n" \
  "Pragma: no-cache\n\n" 
  
  if( len != NULL ) *len = sizeof( SPREAMBLE_STR ) - 1;
  return SPREAMBLE_STR;
}

static
char *get_seperator_text( size_t *len ){
#define SEPERATOR_TEXT "\n--" RANDOMSTRING "\n"  \
  "Content-type: " CONTENTTYPE "\n\n" /* XXX */

  if( len != NULL ) *len = sizeof( SEPERATOR_TEXT ) - 1;
  return SEPERATOR_TEXT;
}

static 
ClientInfo *clientinfo_new( Socket *sock ){
  ClientInfo *res;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  if( (res->writebuf = databuf_new()) == NULL ){
    free( res );
    return NULL;
  }

  res->management_data = NULL;
  res->socket = sock;
  res->state = CINFO_STATE_PREAMBLE;
  res->last_picture_id = -1;
  res->client_type = CLIENT_T_UNINIT;

  return res;
}

static
void clientinfo_dest( ClientInfo *cinfo ){
  databuf_dest( cinfo->writebuf );
  socket_dest( cinfo->socket );
  if( cinfo->management_data ){
    manager_dest_client( cinfo->management_data );
  }
  free( cinfo );
}

/*
 * accept_client:  Accept a client from the listen_socket, and return
 *                 a clientinfo structure containing it.  The new socket
 *                 will be set to non-blocking IO mode.
 *
 * Arguments:      listen_socket = Socket requiring an accept() operation.
 *
 * Return values:  Returns NULL on failure, else a valid pointer to a freshly
 *                 allocated ClientInfo structure.
 */

static
ClientInfo *accept_client( const Socket *listen_socket ){
  Socket *new_sock;
  ClientInfo *res;

  if( (new_sock = socket_accept( listen_socket )) == NULL ){
    camserv_log( MODNAME, "Could not accept new client socket: %s",
		 strerror( errno ));
    return NULL;
  }

  camserv_log( MODNAME, "Accepted new socket: %s", 
	       socket_query_remote_name( new_sock ));

  if( fcntl( socket_query_fd( new_sock ), F_SETFL, O_NONBLOCK ) == -1){
    camserv_log( MODNAME, "Unable to set socket to nonblocking mode!");
    socket_dest( new_sock );
    return NULL;
  }
  
  if( (res = clientinfo_new( new_sock )) == NULL ){
    camserv_log( MODNAME, "Error creating clientinfo structure!");
    socket_dest( new_sock );
    return NULL;
  }

  return res;
}
  
static
int dispatch_pictaker( const char *cmdbuf, const char *picture_mem ){
  int command;

  if( sscanf( cmdbuf, "%d", &command ) != 1 ){
    camserv_log( MODNAME, "Parse error reading data from pictaker!");
    return -1;
  }

  if( command == 0 ) {
    char *new_picture_data;
    int nbytes;

    sscanf( cmdbuf, "%*d %d", &nbytes );
    if( (new_picture_data = malloc( nbytes )) == NULL ){
      camserv_log( MODNAME, "Error allocating memory to manage picture!");
      return -1;
    }

    memcpy( new_picture_data, picture_mem, nbytes );
    if( manager_new_picture( new_picture_data, nbytes, 100 ) == -1 ){
      camserv_log( MODNAME, "Unable to manage picture!");
      free( new_picture_data );
      return -1;
    }
  } else {
    camserv_log( MODNAME, "Unknown pictaker dispatch command: %d", command );
    return -1;
  }
  return 0;
}

static
int write_proxy_client( ClientInfo *cinfo, SockSet *writeset ){
  int bufwrite;

  bufwrite = databuf_write( cinfo->writebuf, socket_query_fd( cinfo->socket ));
  if( bufwrite == -1 ) return -1;
  if( bufwrite == 1 ) return 0;

  /* In this case, we are done sending whatever it was that
     'state' referred to */
  if( cinfo->state == CINFO_STATE_SENDSIZE )
  {
    databuf_buf_set( cinfo->writebuf, cinfo->proxypic_data,
		     ntohl( cinfo->proxypic_size ));
    cinfo->state = CINFO_STATE_PICTURE;
  } else { /* Just finished sending a picture */
    char *pic_data;
    size_t pic_size;
    int pic_id;
    
    /* Remove old info */
    if( cinfo->management_data != NULL ) {
      if( manager_dest_client( cinfo->management_data ) == -1 ){
	camserv_log( MODNAME, "Error destroying client management!");
      }
    }

    cinfo->management_data = manager_new_client(&pic_data, &pic_size, &pic_id);
    if( cinfo->management_data == NULL ){
      camserv_log( MODNAME, "Error managing proxy!  (Picture may not be "
	       "taken yet)");
      sockset_hold( writeset, cinfo->socket );
      return 0;
    }

    if( pic_id == cinfo->last_picture_id ) {
      manager_dest_client( cinfo->management_data );
      cinfo->management_data = NULL;
      /* Proxy sucking too fast */
      sockset_hold( writeset, cinfo->socket );
      return 0;
    }

    camserv_log( MODNAME, "Writing picsize %d to client", (int) pic_size );
    cinfo->proxypic_data = pic_data;
    cinfo->proxypic_size = htonl( pic_size );
    cinfo->last_picture_id = pic_id;
    databuf_buf_set( cinfo->writebuf, &cinfo->proxypic_size,
		     sizeof( cinfo->proxypic_size ));
    cinfo->state = CINFO_STATE_SENDSIZE;
  }

  return 0;
}


static
int write_regular_client( ClientInfo *cinfo, SockSet *writeset ){
  switch(databuf_write( cinfo->writebuf, socket_query_fd( cinfo->socket )))
  {
  case -1 : /* Error */
    return -1;
    break;
  case 0:  /* All done feeding client the current data */
    if( cinfo->state == CINFO_STATE_PREAMBLE   || 
	cinfo->state == CINFO_STATE_SEPERATOR )
    {
      char *pic_data;
      size_t pic_size;
      int pic_id;
      
      cinfo->management_data = manager_new_client( &pic_data, &pic_size,
						   &pic_id );
      if( cinfo->management_data == NULL ){
	camserv_log( MODNAME, "Error managing client! (Picture may not"
		 " be taken yet)");
	/* Wait for the next successful picture to come around */
	sockset_hold( writeset, cinfo->socket );
	return 0;
      }
      
      if( pic_id == cinfo->last_picture_id ) {
	manager_dest_client( cinfo->management_data );
	cinfo->management_data = NULL;
	/* Whoa boy!  Hold on a second! */
	sockset_hold( writeset, cinfo->socket );
	return 0;
      }
      
      databuf_buf_set( cinfo->writebuf, pic_data, pic_size );
      cinfo->last_picture_id = pic_id;
      cinfo->state = CINFO_STATE_PICTURE;

      /* Accounting stuff */
      cinfo->frames++;
      cinfo->bytes += pic_size;
    } else {
      /* Just finished sending a picture */
      char *sep_data;
      size_t sep_size;

      if( manager_dest_client( cinfo->management_data ) == -1 ){
	camserv_log( MODNAME, "Error destroying client management!");
      }
      cinfo->management_data = NULL;
      cinfo->state = CINFO_STATE_SEPERATOR;

      /* For single-frame clients we are done now, and drop them */
      if( cinfo->client_type == CLIENT_T_SINGLE )
	return 1;
      
      /* Check resource limits */
      if( cinfo->max_seconds && 
	  (time( NULL ) - cinfo->create_time) > cinfo->max_seconds ) {
	camserv_log( MODNAME, "Dropping client \"%s\", time limit exceeded",
		     socket_query_remote_name( cinfo->socket ));
	return 1;
      }
      if( cinfo->max_bytes && cinfo->bytes > cinfo->max_bytes ) {
	camserv_log( MODNAME, "Dropping client \"%s\", byte limit exceeded",
		     socket_query_remote_name( cinfo->socket ));
	return 1;
      }
      if( cinfo->max_frames && cinfo->frames > cinfo->max_frames ) {
	camserv_log( MODNAME, "Dropping client \"%s\", frame limit exceeded",
		     socket_query_remote_name( cinfo->socket ));
	return 1;
      }

      /* send a seperator */
      sep_data = get_seperator_text( &sep_size );
      databuf_buf_set( cinfo->writebuf, sep_data, sep_size );
    }
    break;
  case 1:  /* Keep feeding data to the client */
    break;
  }
  return 0;
}

static
void client_remove( list_t *client_sockets, ClientInfo *cinfo ){
  lnode_t *node;

  for( node = list_first( client_sockets ); node != NULL; node=node->next ){
    if( node->data == cinfo ) {
      list_delete( client_sockets, node );
      lnode_destroy( node );
      return;
    }
  }
}

static
void sighandler( int signum ){
  camserv_log( MODNAME, "Received signal: %d",
	   signum );
  if( signum == SIGPIPE )
    return;

  camserv_log( MODNAME, "Aborting!");
  Abort = 1;
}

static
void setup_signals(){
  signal( SIGTERM, sighandler );
  camserv_log( MODNAME, "Setup signals");
}

int main_loop( CamConfig *ccfg, Socket *picture_sock, char *picture_mem  ){
  Socket *listen_socket;
  SockSet *readset = NULL, *writeset = NULL;
  list_t *client_sockets;
  lnode_t *node;
  int cfg_listen_port, highest_fd, picture_client_ready;
  int num_sclients, num_clients;
  ClientInfo *clientinfo, *clientinfo2;

  if( (client_sockets = list_create( -1 )) == NULL)
    return -1;

  cfg_listen_port = camconfig_query_def_int( ccfg, SEC_SOCKET, 
					     "listen_port",
					     CAMCONFIG_DEF_LISTEN_PORT );

  if( (readset = sockset_new()) == NULL ||
      (writeset = sockset_new()) == NULL )
  {
    camserv_log( MODNAME, "Error allocating memory for socksets!");
    if( readset ) sockset_dest( readset );
    if( writeset ) sockset_dest( writeset );
    list_destroy( client_sockets );
    return -1;
  }

  if((listen_socket = socket_serve_tcp( NULL, cfg_listen_port, 100 )) == NULL )
  {
      camserv_log( MODNAME, "Error setting up socket on port \"%d\".  Exiting",
	       cfg_listen_port  );
      list_destroy( client_sockets );
      sockset_dest( readset );
      sockset_dest( writeset );
      return -1;
  }

  highest_fd = MAX( socket_query_fd( listen_socket ), 
		    socket_query_fd( picture_sock ));
  clientinfo = clientinfo_new( listen_socket );
  clientinfo2 = clientinfo_new( picture_sock );

  if( !clientinfo || !clientinfo2 ||
      sockset_add_fd( readset, listen_socket, clientinfo ) == -1 ||
      sockset_add_fd( readset, picture_sock, clientinfo2 ) == -1 )
  {
    camserv_log( MODNAME, "Error adding initial sockets to sockset!");
    sockset_dest( readset );
    sockset_dest( writeset );
    if( clientinfo )  clientinfo_dest( clientinfo );
    if( clientinfo2 ) clientinfo_dest( clientinfo2 );
    list_destroy( client_sockets );
    return -1;
  }

  num_clients = 0;
  num_sclients = 0;
  picture_client_ready = 1;

  setup_signals();
  Abort = 0;
  while( !Abort ){
    int sel_res, i, nset_socks;
    void **set_socks;

    /* Only need to execute this if we have a streaming client */
    if( (num_sclients > 0) && picture_client_ready == 1 ){
      send( socket_query_fd( picture_sock ), "0", sizeof( "0" ), 0 );
      picture_client_ready = 0;
    }

    sockset_reset( readset );
    sockset_reset( writeset );

    sel_res = sockset_select( highest_fd + 1, readset, writeset, NULL );
    /* Service the event */
    if( sel_res == -1 ){
      camserv_log( MODNAME, "select() failure: %s", strerror( errno ));
      break;
    } else if( sel_res == 0 ){
      camserv_log( MODNAME, "Unexpected select() fall through!" );
      continue;
    } 

    /* Readable sockets */
    set_socks = sockset_query_socks( readset );
    nset_socks = sockset_query_nsocks( readset );
    for( i=0; i< nset_socks; i++ ){
      ClientInfo *new_cinfo;

      clientinfo = set_socks[ i ];

      if( clientinfo->socket == listen_socket ) {
	/* New client */
	if( (new_cinfo = accept_client( listen_socket )) == NULL )
	  continue;

	if( (node = lnode_create( new_cinfo )) == NULL ){
	  clientinfo_dest( new_cinfo );
	  continue;
	}

	if( sockset_add_fd( readset, new_cinfo->socket, new_cinfo ) == -1 ){
	  camserv_log( MODNAME, "Failed to add socket %d to socket read set!",
		   socket_query_fd( new_cinfo->socket ));
	  clientinfo_dest( new_cinfo );
	  lnode_destroy( node );
	  continue;
	}

	if( socket_query_fd( new_cinfo->socket ) > highest_fd )
	  highest_fd = socket_query_fd( new_cinfo->socket );

	list_append( client_sockets, node );
	num_clients++;
	/* Init resource limit for this client */
	new_cinfo->create_time = time( NULL );
	new_cinfo->bytes       = 0;
	new_cinfo->frames      = 0;
	new_cinfo->max_seconds = camconfig_query_def_int( ccfg, SEC_SOCKET,
							  "max_seconds", 0 );
	new_cinfo->max_bytes   = camconfig_query_def_int( ccfg, SEC_SOCKET,
							  "max_bytes", 0 );
	new_cinfo->max_frames  = camconfig_query_def_int( ccfg, SEC_SOCKET,
							  "max_frames", 0 );

	/* Send fresh request for a picture */
	send( socket_query_fd( picture_sock ), "0", sizeof( "0" ), 0 );
	picture_client_ready = 0;
	/* Put this read socket on hold until the picture comes back */
	sockset_hold( readset, new_cinfo->socket );	

      } else {
	char cmdbuf[ 1024 ];
	int readlen;

	clientinfo = set_socks[ i ];

	/* Regular joe client, set readable */
	if( (readlen = read( socket_query_fd( clientinfo->socket), cmdbuf, 
			     sizeof( cmdbuf ) - 1)) <= 0 )
	{
	  camserv_log( MODNAME, "Closing socket: %s", 
		       socket_query_remote_name( clientinfo->socket ));

	  if (clientinfo->client_type == CLIENT_T_BROWSER ||
	      clientinfo->client_type == CLIENT_T_PROXY) {
	      num_sclients--;
	  }
	  client_remove( client_sockets, clientinfo );
	  sockset_del_fd( readset, clientinfo->socket );
	  sockset_unhold_all( writeset );
	  sockset_del_fd( writeset, clientinfo->socket );
	  clientinfo_dest( clientinfo );
	  num_clients--;
	} else {
	  if( clientinfo->socket == picture_sock ) {
	    if( dispatch_pictaker( cmdbuf, picture_mem ) == -1 )
	      camserv_log( MODNAME, "Pictaker dispatch failure!");
	    sockset_unhold_all( writeset );
	    /* Release the read hold as the picture has now been taken */
	    sockset_unhold_all( readset );
	    picture_client_ready = 1;
	  } else {
	    /* Information from a regular client */
	    cmdbuf[ readlen ] = '\0';
	    if( clientinfo->client_type == CLIENT_T_UNINIT ) {
	      char *preamble;
	      size_t pre_size;

	      /* Figure out what type of client we have */
	      if( !strncmp( cmdbuf, "GET", 3 )) {
		if( strstr( cmdbuf, "/singleframe" )) {
		  clientinfo->client_type = CLIENT_T_SINGLE;
		} else {
		  clientinfo->client_type = CLIENT_T_BROWSER;
		  num_sclients++;
	        }
	      } else if( !strncmp( cmdbuf, "PROXY", 5 )) {
		clientinfo->client_type = CLIENT_T_PROXY;
		/* Here we are in the same state as being done writing a pic */
		clientinfo->state       = CINFO_STATE_PICTURE;
		num_sclients++;	
		databuf_buf_set( clientinfo->writebuf, NULL, 0 ); 
	      } else 
		clientinfo->client_type = CLIENT_T_BROWSER;

	      if( clientinfo->client_type != CLIENT_T_PROXY ) {
		/* Send the initial preamble.  Only now we can decide which 
		   type of preamble to send (single vs. multi-part) */
		if( clientinfo->client_type == CLIENT_T_SINGLE )
		  preamble = get_single_preamble_text( &pre_size );
		else
		  preamble = get_multi_preamble_text( &pre_size );
		databuf_buf_set( clientinfo->writebuf, preamble, pre_size );
	      }

	      if( sockset_add_fd( writeset, clientinfo->socket, 
				  clientinfo ) == -1 )
	      {
  		  camserv_log( MODNAME, "Failed to add socket %d to write set!",
			   socket_query_fd( clientinfo->socket ));
	      }
	  } 
	} 
      } 
    } 
  } 

    if( set_socks != NULL ) free( set_socks );

    /* Writable sockets */
    set_socks = sockset_query_socks( writeset );
    nset_socks = sockset_query_nsocks( writeset );
    for( i=0; i< nset_socks; i++ ){
      ClientInfo *cinfo;

      cinfo = set_socks[ i ];
      if( cinfo->client_type == CLIENT_T_BROWSER ||
	  cinfo->client_type == CLIENT_T_SINGLE ) 
      {
	int result;

	if( (result = write_regular_client( cinfo, writeset )) != 0 ){
	  /* result: 1=close requested, -1=error detected */
	  if( result == -1 )
	    camserv_log( MODNAME, "Databuf write error on socket: %s\n",
			 socket_query_remote_name( cinfo->socket ));
	  
	  if (cinfo->client_type == CLIENT_T_BROWSER) {
	      num_sclients--;
	  }

	  client_remove( client_sockets, cinfo );
	  sockset_del_fd( readset, cinfo->socket );
	  sockset_del_fd( writeset, cinfo->socket );
	  clientinfo_dest( cinfo );
	  num_clients--;
	}
      } else {
	if( write_proxy_client( cinfo, writeset ) == -1 ){
	  camserv_log( MODNAME, "Databuf write error on socket: %d",
		   socket_query_fd( cinfo->socket ));

	  /* Should be proxy, but better check */
	  if (cinfo->client_type == CLIENT_T_PROXY) {
	      num_sclients--;
	  }
	  client_remove( client_sockets, cinfo );
	  sockset_del_fd( readset, cinfo->socket );
	  sockset_del_fd( writeset, cinfo->socket );
	  clientinfo_dest( cinfo );
	  num_clients--;
	}
      }
    }
    if( set_socks != NULL ) free( set_socks );
  }

  camserv_log( MODNAME, "Aborting.");
  sockset_dest( readset );
  sockset_dest( writeset );

  for( node = list_first( client_sockets) ; node; 
       node=list_next( client_sockets, node ))
  {
    clientinfo_dest( node->data );
  }

  /* Tell the picture taker to get out!  Get out! */
  camserv_log( MODNAME, "Closing picture taker");
  send( socket_query_fd( picture_sock ), "9", sizeof( "9" ), 0 );
  sleep( 3 );
  camserv_log( MODNAME, "done\n");

  list_destroy_nodes( client_sockets );
  list_destroy( client_sockets );
  socket_dest( listen_socket );
  return 0;
}

