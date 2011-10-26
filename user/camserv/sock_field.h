#ifndef SOCK_FIELD_DOT_H
#define SOCK_FIELD_DOT_H

#include "databuf.h"
#include "socket.h"
#include "sockset.h"

#define SOCKFIELD_CLOSE     ( 1 << 0 )
#define SOCKFIELD_OK        ( 1 << 1 ) 
#define SOCKFIELD_SHUTDOWN  ( 1 << 2 )

typedef struct sock_field_data SockField_Data;
typedef int (*SockField_InitFunc)( SockField_Data *sfdata, void *sys_cldata );
typedef void (*SockField_PreCloseFunc)( Socket *sock, void *cldata,
					void *sys_cldata);
typedef int (*SockField_ReadFunc)( SockField_Data *sfdata, Socket *sock,
				    void *);
typedef int (*SockField_WriteFunc)( SockField_Data *sfdata, Socket *sock,
				    void *);
typedef void (*SockField_TimeoutFunc)( SockField_Data *sfdata, 
				      void *sys_cldata );
typedef void (*SockField_AcceptFunc)( SockField_Data *sfdata, Socket *sock,
				      void *sys_cldata );



extern int sock_field_manage_socket( SockField_Data *sfdata, Socket *sock, 
				     void *cldat );
extern void sock_field_unhold_write( SockField_Data *sfdata );
extern void sock_field_hold_write( SockField_Data *sfdata, Socket *socket );
extern int sock_field( Socket *listen_sock,
		       void *sys_cldata,
		       SockField_InitFunc init_func,
		       SockField_AcceptFunc accept_func,
		       SockField_ReadFunc read_func,
		       SockField_WriteFunc write_func,
		       SockField_PreCloseFunc preclose_func,
		       SockField_TimeoutFunc timeout_func,
		       struct timeval *timeout );
#endif
