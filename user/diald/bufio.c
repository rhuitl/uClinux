/*
 * bufio.c - Buffered, selectable I/O on pipes.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

void pipe_init(int fd,PIPE *pipe)
{
    char buf[2];
    pipe->fd = fd;
    pipe->count = 0;
    fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
    /* clear out any old garbage from the FIFO */
    while (read(fd,buf,1) > 0);
}

/* Read from the file descriptor, and
 * the return the number of characters in the buffer.
 * This all assumes that there are some characters to read.
 */

int pipe_read(PIPE *pipe)
{
    int i;
    if (pipe->count == sizeof(pipe->buf)) {
	return pipe->count;	/* No room for more input */
    }
    i = read(pipe->fd, pipe->buf+pipe->count, sizeof(pipe->buf)-pipe->count);
    if (i > 0) {
	pipe->count += i;
	return pipe->count;
    } else {
	if (errno == EAGAIN)
	    syslog(LOG_ERR,"EOF on control fifo. Closing fifo.");
	else
	    syslog(LOG_ERR,"Error on control fifo: %m");
	return -1;	/* error! shut down reader... */
    }
}

/* Drop count characters from the pipe's buffer */
void pipe_flush(PIPE *pipe,int count)
{
    if (count >= pipe->count) {
	pipe->count = 0;
    } else {
       pipe->count -= count;
       memmove(pipe->buf, pipe->buf+count, pipe->count);
    }
}
