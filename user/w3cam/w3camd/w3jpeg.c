/*
 * w3jpeg.c
 * plain io destination manager (write())
 *
 * Copyright (C) 1998 - 2000 Rasca, Berlin
 * EMail: thron@gmx.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <unistd.h>
#include <jpeglib.h>
#include <jerror.h>
#include "w3jpeg.h"

typedef struct {
	struct jpeg_destination_mgr pub;
	int fd;
	JOCTET *buffer;
} my_destination_mgr;

typedef my_destination_mgr *my_dest_ptr;
#define OUTPUT_BUF_SIZE 2048


/*
 * initialize buffer
 */
METHODDEF(void)
init_destination (j_compress_ptr cinfo)
{
	my_dest_ptr dest = (my_dest_ptr) cinfo->dest;

	dest->buffer = (JOCTET *)
		(*cinfo->mem->alloc_small) ((j_common_ptr) cinfo, JPOOL_IMAGE,
		OUTPUT_BUF_SIZE * sizeof(JOCTET));

	dest->pub.next_output_byte = dest->buffer;
	dest->pub.free_in_buffer = OUTPUT_BUF_SIZE;
}

/*
 * flush buffer to filedescriptor
 */
METHODDEF(boolean)
empty_output_buffer (j_compress_ptr cinfo)
{
	my_dest_ptr dest = (my_dest_ptr) cinfo->dest;
	if (write (dest->fd, dest->buffer, OUTPUT_BUF_SIZE) != OUTPUT_BUF_SIZE) {
#ifdef DEBUG_JPEG
		fprintf (stderr, "%s: empty_output_buffer()\n", __FILE__);
#endif
		return (FALSE);
		ERREXIT(cinfo, JERR_FILE_WRITE);
	}
	dest->pub.next_output_byte = dest->buffer;
	dest->pub.free_in_buffer = OUTPUT_BUF_SIZE;
	return (TRUE);
}

/*
 */
METHODDEF(void)
term_destination(j_compress_ptr cinfo)
{
	my_dest_ptr dest = (my_dest_ptr) cinfo->dest;
	size_t datacount = OUTPUT_BUF_SIZE - dest->pub.free_in_buffer;

	if (datacount > 0) {
		if (write (dest->fd, dest->buffer, datacount) != datacount) {
#ifdef DEBUG_JPEG
			fprintf (stderr, "%s: term_destination()\n", __FILE__);
#endif
			return;
			ERREXIT(cinfo, JERR_FILE_WRITE);
		}
	}
}


/*
 */
GLOBAL(void)
jpeg_io_dest (j_compress_ptr cinfo, int fd)
{
	my_dest_ptr dest;
	if (cinfo->dest == NULL) {
		cinfo->dest = (struct jpeg_destination_mgr *)
			(*cinfo->mem->alloc_small) ((j_common_ptr)cinfo, JPOOL_PERMANENT,
			sizeof(my_destination_mgr));
	}
#ifdef DEBUG_JPEG
			fprintf (stderr, "%s: jpeg_io_dest()\n", __FILE__);
#endif
	dest = (my_dest_ptr) cinfo->dest;
	dest->pub.init_destination = init_destination;
	dest->pub.empty_output_buffer = empty_output_buffer;
	dest->pub.term_destination = term_destination;
	dest->fd = fd;
}

