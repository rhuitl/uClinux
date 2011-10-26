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
#include <stdarg.h>

#include "camserv.h"
#include "jpgstuff.h"
#include "log.h"

#define FAIRY_DUST 0x10203040

#define MODNAME "jpgstuff"

/*
 * JPEG_error_exit:  Exit routine called when an error happens in the
 *                   libjpeg library 
 */

static
void JPEG_error_exit( j_common_ptr cinfo ){
  JPEG_Wrapper *wrap_cldat = (JPEG_Wrapper *)(cinfo->client_data);

  camserv_log( MODNAME, "JPGSTUFF error exit called");
  (*cinfo->err->output_message)( cinfo );
  longjmp( wrap_cldat->setjmp_buffer, 1 );
}

/*
 * setup_jpeg_output_buffer:  Initialize the output buffer for the jpeg
 *                            wrapper routines.
 *
 * Arguments:                 jwrap = Wrapper to setup the buffer for
 *                            jparams = parameter information about the width
 *                                      and height of the images
 *
 * Return values:             Returns -1 on failure 0 on sucess.
 */

static
int setup_jpeg_output_buffer( JPEG_Wrapper *jwrap, const JPEG_Params *jparams){
  JOCTET *buffer;
  size_t buf_size;

  /* XXX -- This is REALLY crude, as we seem to be allocating more
     than the jpeg could ever need to use .. it'd be better if we had
     some actual tuning on this */
  buf_size = jparams->width * jparams->height * 
    (jparams->is_black_white ? 1 : 3);

  if( ( buffer = malloc( buf_size * sizeof( *buffer))) == NULL )
    return -1;

  jwrap->jpeg_output_buffer = buffer;
  jwrap->jpeg_buffer_size = buf_size;
  jwrap->user_specd_buffer = 0;
  return 0;
}

/*
 * init_destination:  Callback for the jpeg library to inform libjpg where
 *                    it needs to be placing the output jpeg.
 */

static
void init_destination( j_compress_ptr cinfo ){
  JPEG_Wrapper *jwrap = (JPEG_Wrapper *)cinfo->client_data;
  
  if( jwrap->magic_fairy_dust != FAIRY_DUST )
    camserv_log( MODNAME, "Possibly bad jwrap passed into init_destination");
    
  cinfo->dest->next_output_byte = jwrap->jpeg_output_buffer;
  cinfo->dest->free_in_buffer = jwrap->jpeg_buffer_size;
}

/*
 * empty_output_buffer:  Callback for the jpeg library when libjpg thinks
 *                       it has filled up the buffer.  We should allocate 
 *                       enough so that this really only needs to start over
 *                       at the beginning.
 */

static
int empty_output_buffer( j_compress_ptr cinfo ){
  JPEG_Wrapper *jwrap = (JPEG_Wrapper *)cinfo->client_data;

  if( jwrap->magic_fairy_dust != FAIRY_DUST )
    camserv_log( MODNAME, "Possibly bad jwrap passed into empty_output_buffer");
  
  if( cinfo->dest->free_in_buffer <= 0 ){
    /* Problem .. we didn't allocate enuf! */
    camserv_log( MODNAME, "OUCH!  Misallocation of jpg storage! (%d)",
	     cinfo->dest->free_in_buffer );
    exit(-1);
  }

  cinfo->dest->next_output_byte = jwrap->jpeg_output_buffer;
  cinfo->dest->free_in_buffer = jwrap->jpeg_buffer_size;
  return TRUE;
}

/*
 * term_destination:  Callback for the jpeg library when libjpg has finished
 *                    with the current processing
 */

static
void term_destination( j_compress_ptr cinfo ){
  JPEG_Wrapper *jwrap = (JPEG_Wrapper *)cinfo->client_data;

  if( jwrap->magic_fairy_dust != FAIRY_DUST )
    camserv_log( MODNAME, "Possibly bad jwrap passed into term_destination");

  jwrap->actual_jpeg_size = cinfo->dest->next_output_byte -
    jwrap->jpeg_output_buffer;
}

/*
 * JPEG_Wrapper_initialize:  Initialize a jpeg wrapper, given some 
 *                           parameters.  This sets up all the information
 *                           to do jpeg processing.
 *
 * Arguments:                jwrap = Storage location to put jpeg wrapper
 *                                   info
 *                           jparams = Parameters about the JPEGs
 *                           output_buffer = Buffer to place jpegs on 
 *                                           compression completion.  The
 *                                           calling routine must free the
 *                                           data when it is no longer being
 *                                           used.
 *                             
 * Return values:            Returns -1 on failure, 0 on success.
 */

int
JPEG_Wrapper_initialize( JPEG_Wrapper *jwrap, const JPEG_Params *jparams,
			 char *output_buffer, int outbuf_size  )
{
  if( output_buffer == NULL ){
    if( setup_jpeg_output_buffer( jwrap, jparams ) == -1 )
      return -1;
  } else {
    jwrap->jpeg_output_buffer = output_buffer;
    jwrap->jpeg_buffer_size = outbuf_size;
    jwrap->user_specd_buffer = 1;
  }

  jwrap->cinfo.err = jpeg_std_error( &jwrap->err_mgr );
  jwrap->err_mgr.error_exit = JPEG_error_exit;

  jpeg_create_compress( &jwrap->cinfo );

  /* Initialize destination information, because 
     we are going to memory .. not some janky file */
  jwrap->dest_mgr.init_destination = init_destination;
  jwrap->dest_mgr.empty_output_buffer = empty_output_buffer;
  jwrap->dest_mgr.term_destination = term_destination;
  jwrap->cinfo.dest = &jwrap->dest_mgr;
  
  jwrap->cinfo.image_width = jparams->width;
  jwrap->cinfo.image_height = jparams->height;
  
  jwrap->is_black_white = jparams->is_black_white;
  if( jparams->is_black_white ){
    jwrap->cinfo.input_components = 1;
    jwrap->cinfo.in_color_space = JCS_GRAYSCALE;
  } else {
    jwrap->cinfo.input_components = 3;
    jwrap->cinfo.in_color_space = JCS_RGB;
  }

  jpeg_set_defaults( &jwrap->cinfo );

  jpeg_set_quality( &jwrap->cinfo, jparams->quality, TRUE );

  jwrap->magic_fairy_dust = FAIRY_DUST;
  jwrap->cinfo.client_data = jwrap;
  return 0;
}

/*
 * JPEG_Wrapper_deinitialize:  Deinitialize the jpeg wrapper, and free
 *                             all information associated with it.  If the
 *                             caller passed in an output buffer on creation,
 *                             it will be freed on this deinit 
 */

void
JPEG_Wrapper_deinitialize( JPEG_Wrapper *jwrap ){
  if( jwrap->magic_fairy_dust != FAIRY_DUST )
    camserv_log( MODNAME, 
		 "Possibly bad jwrap passed into JPEG_Wrapper_deinitialize");

  jpeg_destroy_compress( &jwrap->cinfo );
  if( jwrap->user_specd_buffer == 0 )
    free( jwrap->jpeg_output_buffer );
}


/*
 * JPEG_Wrapper_do_compress:  JPG compress a picture.  
 *
 * Arguments:                 jwrap = Jwrap as returned by the init procedure
 *                            width = Width of the image
 *                            height = Height of the image
 *                            image_data = Image to compress
 *
 */

void
JPEG_Wrapper_do_compress( JPEG_Wrapper *jwrap, 
			  unsigned int width, unsigned int height,
			  JSAMPLE *image_data )
{
  JSAMPROW row_pointer[1];
  int row_stride;

  if( jwrap->is_black_white )
    row_stride = width;
  else
    row_stride = width * 3;

  jpeg_start_compress( &jwrap->cinfo, TRUE );
  while( jwrap->cinfo.next_scanline < jwrap->cinfo.image_height ){
    row_pointer[0] = &image_data[ jwrap->cinfo.next_scanline * row_stride];
    jpeg_write_scanlines( &jwrap->cinfo, row_pointer, 1 );
  }
  jpeg_finish_compress( &jwrap->cinfo );
}

