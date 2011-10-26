/*
tunnel.h

Copyright (C) 1999 Lars Brinkhoff.  See COPYING for terms and conditions.
*/

/*
This is the programming interface to the HTTP tunnel.  It consists
of the following functions:

Tunnel *tunnel_new_client (const char *host, int host_port,
                           const char *proxy, int proxy_port,
			   size_t content_length);

  Create a new HTTP tunnel client.

Tunnel *tunnel_new_server (int port,
			   size_t content_length);

  Create a new HTTP tunnel server.  If LENGTH is 0, the Content-Length
  of the HTTP GET response will be determined automatically in some way.

int tunnel_connect (Tunnel *tunnel);

  Open the tunnel.  (Client only.)

int tunnel_accept (Tunnel *tunnel);

  Accept a tunnel connection.  (Server only.)

int tunnel_pollin_fd (Tunnel *tunnel);

  Return a file descriptor that can be used to poll for input from
  the tunnel.

ssize_t tunnel_read (Tunnel *tunnel, void *data, size_t length);
ssize_t tunnel_write (Tunnel *tunnel, void *data, size_t length);

  Read or write to the tunnel.  Same semantics as with read() and
  write().  Watch out for return values less than LENGTH.

int tunnel_padding (Tunnel *tunnel, size_t length);

  Send LENGTH pad bytes.

int tunnel_maybe_pad (Tunnel *tunnel, size_t length);

  Pad to nearest even multiple of LENGTH.

int tunnel_close (Tunnel *tunnel);

  Close the tunnel.

void tunnel_destroy (Tunnel *tunnel);
*/

#ifndef TUNNEL_H
#define TUNNEL_H

#include "config.h"
#include <sys/types.h>

#define DEFAULT_CONNECTION_MAX_TIME 300

typedef struct tunnel Tunnel;

extern Tunnel *tunnel_new_client (const char *host, int host_port,
				  const char *proxy, int proxy_port,
				  size_t content_length);
extern Tunnel *tunnel_new_server (int port, size_t content_length);
extern int tunnel_connect (Tunnel *tunnel);
extern int tunnel_accept (Tunnel *tunnel);
extern int tunnel_pollin_fd (Tunnel *tunnel);
extern ssize_t tunnel_read (Tunnel *tunnel, void *data, size_t length);
extern ssize_t tunnel_write (Tunnel *tunnel, void *data, size_t length);
extern ssize_t tunnel_padding (Tunnel *tunnel, size_t length);
extern int tunnel_maybe_pad (Tunnel *tunnel, size_t length);
extern int tunnel_setopt (Tunnel *tunnel, const char *opt, void *data);
extern int tunnel_getopt (Tunnel *tunnel, const char *opt, void *data);
extern int tunnel_close (Tunnel *tunnel);
extern void tunnel_destroy (Tunnel *tunnel);

#endif /* TUNNEL_H */
