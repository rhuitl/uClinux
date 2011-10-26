#ident "$Id: vhangup.c,v 1.1 1999/01/04 21:47:36 gert Exp $ Copyright (c) Gert Doering"

/* vhangup.c
 *
 * invalidate all file descriptors for a given tty device
 *
 *  - works only on Linux and BSD Unix.
 *  - must be run as an external process, because mgetty does not have
 *    a controlling tty, and vhangup() can not operate on a file descriptor.
 *
 * $Log: vhangup.c,v $
 * Revision 1.1  1999/01/04 21:47:36  gert
 * add vhangup
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

int main( int argc, char ** argv )
{
int fd;

    if ( argc != 2 || strncmp( argv[1], "/dev/", 5 ) != 0 )
    {
	fprintf( stderr, "usage: %s /dev/tty<x>\n", argv[0] );
	exit(1);
    }

    if ( ( fd = open( argv[1], O_RDWR | O_NDELAY ) ) < 0 )
    {
	fprintf( stderr, "%s: can't open %s: %s\n",
		  argv[0], argv[1], strerror(errno) );
	exit(2);
    }

    if ( vhangup() < 0 )
    {
	fprintf( stderr, "%s: vhangup() failed: %s\n",
		  argv[0], strerror(errno) );
	exit(3);
    }

    close(fd);
    return 0;
}
