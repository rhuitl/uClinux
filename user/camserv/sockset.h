#ifndef SOCKSET_DOT_H
#define SOCKSET_DOT_H

#include "socket.h"

typedef struct _sockset_st SockSet;

extern SockSet *sockset_new();
extern void sockset_dest( SockSet *sset );
extern int sockset_add_fd( SockSet *sset, const Socket *sock, 
			   const void *cldata );
extern int sockset_del_fd( SockSet *sset, const Socket *sock );
extern void **sockset_query_socks( const SockSet *sset );
extern int sockset_query_nsocks( const SockSet *sset );
extern void sockset_reset( SockSet *sset );
extern int sockset_select( int highest_fd, 
			   SockSet *readset, SockSet *writeset, 
			   struct timeval *tout );
extern int sockset_hold( SockSet *sset, const Socket *sock );
extern void sockset_unhold_all( SockSet *sset );

#endif
