#ifndef SOCKET_DOT_H
#define SOCKET_DOT_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

typedef struct socket_st Socket;

extern Socket *socket_serve_tcp( const char *hname, int port, int backlog );
extern Socket *socket_accept( const Socket *listen_sock );
extern Socket *socket_new();
extern const char *socket_query_remote_name( Socket *sock );
extern int socket_query_fd( const Socket *sock );
extern void socket_dest( Socket *sock );
extern Socket **socket_unix_pair( int type );
extern void socket_unix_pair_dest( Socket **sockpair );
extern Socket *socket_connect( const char *remote_name, int remote_port );
extern int socket_set_nonblock( Socket *sock );
extern void socket_zero( Socket *sock );

#endif
