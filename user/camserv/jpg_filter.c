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
#include "log.h"
#include "camconfig.h"
#include "video.h"
#include "filter.h"
#include "jpgstuff.h"

#define MODNAME "jpg_filter"

typedef struct jpg_info_st {
  JPEG_Wrapper jwrap;
  JPEG_Params jparams;
  char *jpeg_data;
  int is_last_filter;
} JPG_Info;

/*
 * filter_init:  Standard filter initialization routine.
 *
 * Filter variables:  jpgmod_quality = Number between 0 and 100 of the jpeg
 *                                     quality to use when compressing
 */                 

void *filter_init( CamConfig *ccfg, char *section_name ){
  JPG_Info *jinfo;
  int err, nbytes;

  if( (jinfo = malloc( sizeof( *jinfo ))) == NULL ){
    camserv_log( MODNAME,
		 "FATAL!  Could not allocate %d bytes!", sizeof( *jinfo ));
    return NULL;
  }
  
  /* Reconfigure based upon camcfg information */
  jinfo->jparams.quality = camconfig_query_def_int( ccfg, section_name, 
						    "quality",10);
  jinfo->jparams.width = camconfig_query_int( ccfg, SEC_VIDEO, 
					      VIDCONFIG_WIDTH, &err );
  if( err ) camserv_log( MODNAME, "Config inconsistancy! (width)");

  jinfo->jparams.height = camconfig_query_int( ccfg, SEC_VIDEO,
					       VIDCONFIG_HEIGHT, &err );
  if( err ) camserv_log( MODNAME, "Config inconsistancy! (height)");

  jinfo->jparams.is_black_white = camconfig_query_int( ccfg, SEC_VIDEO,
						       VIDCONFIG_ISB_N_W,
						       &err );
  if( err ) camserv_log( MODNAME, "Config inconsistancy! (isb_n_w)");
  
  nbytes = jinfo->jparams.width * jinfo->jparams.height *
    (jinfo->jparams.is_black_white ? 1 : 3 );
  if( (jinfo->jpeg_data = malloc( nbytes )) == NULL ){
    camserv_log( MODNAME, 
		"FATAL!  Unable to allocate %d bytes for jpeg picture",nbytes);
    free( jinfo );
    return NULL;
  }

  if( JPEG_Wrapper_initialize( &jinfo->jwrap, &jinfo->jparams,
			       jinfo->jpeg_data, nbytes ) == -1 ){
    camserv_log( MODNAME, "FATAL!  Unable to initialize jpg wrapper!");
    free( jinfo->jpeg_data );
    free( jinfo );
    return NULL;
  }
  return jinfo;
}

void filter_deinit( void *filter_dat ){
  JPG_Info *jinfo = filter_dat;

  JPEG_Wrapper_deinitialize( &jinfo->jwrap );
  free( jinfo->jpeg_data );
  free( jinfo );
}

void filter_func( char *in_data, char **out_data, void *cldat, 
		  const Video_Info *vinfo_in, Video_Info *vinfo_out )
{
  JPG_Info *jinfo = cldat;
  int is_last_filter;
  JOCTET *last_buf_value;

  is_last_filter = (*out_data != NULL ) && (in_data != *out_data);

  *vinfo_out = *vinfo_in;

  last_buf_value = jinfo->jwrap.jpeg_output_buffer;
  if( is_last_filter ) {
    /* Small optimization:  we can output directly to the final 
       picture memory */
    jinfo->jwrap.jpeg_output_buffer = (JOCTET *)*out_data;
  }  else {
    jinfo->jwrap.jpeg_output_buffer = (JOCTET *)jinfo->jpeg_data;
    *out_data = jinfo->jpeg_data;
  }

  JPEG_Wrapper_do_compress( &jinfo->jwrap, vinfo_in->width, vinfo_in->height,
			    (JSAMPLE *)in_data );

  vinfo_out->nbytes = jinfo->jwrap.actual_jpeg_size;

  if( !is_last_filter ) {
    memcpy( jinfo->jpeg_data, jinfo->jwrap.jpeg_output_buffer, 
	    jinfo->jwrap.actual_jpeg_size );
  }

  jinfo->jwrap.jpeg_output_buffer = last_buf_value;
}

void filter_validation(){
  Filter_Init_Func init = filter_init;
  Filter_Deinit_Func deinit = filter_deinit;
  Filter_Func_Func func = filter_func;

  if( init != NULL && deinit != NULL && func != NULL ) return;
}

/*
 * modinfo_query:  Routine to return information about the variables
 *                 accessed by this particular module.
 *
 * Return values:  Returns a malloced ModInfo structure, for which
 *                 the caller must free, or NULL on failure.
 */

ModInfo *modinfo_query(){
  ModInfo *res;

  if( (res = modinfo_create( 1 )) == NULL )
    return NULL;

  modinfo_varname_set( res, 0, "quality" );
  modinfo_desc_set( res, 0, "JPEG Quality (0->100)" );
  res->vars[ 0 ].type = MODINFO_TYPE_INT;
  
  return res;
}
