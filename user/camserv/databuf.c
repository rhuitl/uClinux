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
#include <unistd.h>

#include "databuf.h"

struct _databuf_st {
  void *buffer;
  size_t buffer_size;
  void *data_p;
};

/*
 * databuf_new:  Create and initialize a databuf structure
 *
 * Return values:  Returns NULL on failure, else a pointer to a freshly
 *                 alloced chunk of memory
 */

DataBuf *databuf_new(){
  DataBuf *res;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  res->buffer = NULL;
  res->buffer_size = 0;
  res->data_p = NULL;
  return res;
}

/*
 * databuf_dest:  Destroy a databuffer structure  If one has previously
 *                set a buffer data segment to the databuffer, It is the
 *                callers duty to free it
 */

void databuf_dest( DataBuf *dbuf ){
  free( dbuf );
}

/*
 * databuf_buf_set:  Set the buffer of a databuffer.  All of the positions
 *                   for the location of the databuffer will be reset.
 */

void databuf_buf_set( DataBuf *dbuf, void *new_buffer, size_t buf_size ){
  dbuf->buffer = new_buffer;
  dbuf->buffer_size = buf_size;
  dbuf->data_p = new_buffer;
}

/*
 * databuf_write:  Attempt to write data from the databuffer to a given file
 *                 descriptor.  If the entire buffer cannot be written for
 *                 some reason, the routine will store the location of the
 *                 next information to write.  databuf_buf_set  must be called
 *                 prior to calling this function.
 *
 * Arguments:      dbuf = Databuffer containing data to write.
 *                 fd   = File descriptor to write to
 *
 * Return values:  Returns 0 if all the data in the databuffer has been written
 *                 to the fd.  -1 if an error occurs, and 1 if there is still
 *                 data to be written.
 */

int databuf_write( DataBuf *dbuf, int fd ){
  ssize_t res;

  /* Attempt to write the rest of the buffer into the fd */
  res = write( fd, dbuf->data_p, 
	       (char *)dbuf->buffer + dbuf->buffer_size - (char *)dbuf->data_p
	       );
  if( res == -1 )
    return -1;
  
  dbuf->data_p = (char *)dbuf->data_p + res;
  
  if( (char *)dbuf->data_p - (char *)dbuf->buffer == dbuf->buffer_size )
    return 0; /* All done */

  return 1;
}


/*
 * databuf_read:  Attempt to read data from a file descriptor into a given
 *                databuffer.  If the entire data cannot be read for some
 *                reason, the routine will store the location of the next
 *                information to read.  databuf_buf_set  must be called 
 *                prior to calling this function, to give the databuffer
 *                a location to read the data into. 
 *
 * WARNING:       databuf_read and databuf_write should NOT be mix-matched.
 *
 * Arguments:     dbuf = Databuffer to store read data
 *                fd   = Filedescriptor to read from.
 * 
 * Return values: Returns 0 if all the data requested has been read.  -1
 *                if an error occurs, and 1 if there is still more data to
 *                be read.
 */

int databuf_read( DataBuf *dbuf, int fd ){
  ssize_t res;

  /* Attempt to read the rest of the buffer from the fd */
  res = read( fd, dbuf->data_p,
	      (char *)dbuf->buffer + dbuf->buffer_size - (char *)dbuf->data_p);
  if( res <= 0 )
    return -1;

  dbuf->data_p = (char *)dbuf->data_p + res;
  
  if( (char *)dbuf->data_p - (char *)dbuf->buffer == dbuf->buffer_size )
    return 0; /* All done */

  return 1;
}
