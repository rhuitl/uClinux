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
#include <string.h>
#include <dlfcn.h>

#include "log.h"
#include "camconfig.h"
#include "filter.h"
#include "video.h"

#define MODNAME  "filter"

struct filter_st {
  char section_name[ MAX_SECTION_NAME + 1 ];
  Filter_Init_Func filter_init;
  Filter_Deinit_Func filter_deinit;
  Filter_Func_Func filter_func;
  ModInfo_QueryFunc modinfo_func;
  void *filter_cldat;
};

/*
 * filter_list_init:  Initialize the filter list.  This routine will
 *                    loop through all of the filters and notify them
 *                    all that they need to initialize (in addition to
 *                    storing returned clientdata information from the
 *                    filter module)
 *
 * Arguments:         filters = Filter list as returned by filter_setup
 *                    ccfg    = Camera configuration
 */

void filter_list_init( Filter *filters, CamConfig *ccfg ){
  int i;

  if( filters == NULL ) return;

  for( i=0; filters[ i ].filter_init != NULL; i++ ){
    void *fres;

    fres = filters[ i ].filter_init( ccfg, filters[ i ].section_name );
    filters[ i ].filter_cldat = fres;
  }
}

/*
 * filter_list_deinit:  Deinitialize all of the filters in the filter list.
 *
 * Arguments:           filters = Filter list as returned by filter_setup
 */

void filter_list_deinit( Filter *filters ){
  int i;

  for( i=0; filters[ i ].filter_init != NULL; i++ ){
    filters[ i ].filter_deinit( filters[ i ].filter_cldat );
  }
}

/*
 * filter_list_process:  Process picture information through all of the
 *                       filters.  The filters may change the composition
 *                       of the picture, the size of it, etc.  It is required
 *                       that the locations for storing the pictures be at 
 *                       least as big as the maximum picture size.
 *
 * Arguments:            filters = Filter list to pass the pictures through
 *                       picture = Input picture to filter
 *                       final_pic_out = Location to place final picture
 *                       vinfo = Information about 'picture'
 *                       out_vinfo = Information about 'final_pic_out'
 */

void filter_list_process( Filter *filters, char *picture, char *final_pic_out,
			  const Video_Info *vinfo, Video_Info *out_vinfo )
{
  Video_Info last_vinfo;
  char *last_out;
  int i;

  last_out = picture;
  last_vinfo = *vinfo;
  for( i=0; filters[ i ].filter_init != NULL; i++ ){
    char *outdata;
    Video_Info outvinfo;
    int is_last_filter;

    is_last_filter = (filters[ i + 1 ].filter_init == NULL ? 1 : 0);

    if( is_last_filter )
      outdata = final_pic_out;
    else
      outdata = NULL;

    filters[ i ].filter_func( last_out, &outdata, filters[ i ].filter_cldat,
			      &last_vinfo, &outvinfo );
    last_out = outdata;
    last_vinfo = outvinfo;
  }

  if( last_out != final_pic_out ){
    memmove( final_pic_out, last_out, last_vinfo.nbytes );
  }

  *out_vinfo = last_vinfo;
}

/*
 * filter_setup:  Attempt to use filter information from the cam config to
 *                load the filter libraries.
 *                
 * Arugments:     ccfg = Camera configuration
 *                reserr = Err result.  == 0 on no error, 1 if an error occured
 *          
 * Return values:  reserr should be checked for error results.  The return
 *                 value is filter information to be passed into other filter_
 *                 commands.
 */

Filter *filter_setup( CamConfig *ccfg, int *reserr ){
  int err, nfilters, i;
  const char *val;
  char key[ 1024 ];
  void *dlhandle;
  Filter *filters;

  nfilters = camconfig_query_int( ccfg, SEC_FILTERS, "num_filters", &err );
  if( err ) {
    *reserr = 0;
    return NULL;
  }

  if( (filters = malloc( sizeof( *filters ) * (nfilters+1) )) == NULL ){
    camserv_log( MODNAME, "Error allocating memory for filter storage!" );
    *reserr = 1;
    return NULL;
  }

  for( i=0; i< nfilters; i++ ){
    sprintf( key, "filter%d_section", i );
    if( (val = camconfig_query_str( ccfg, SEC_FILTERS, key )) == NULL ){
      camserv_log( MODNAME, "[%s]:%s key/val pair not "
		   "found in cfg file", SEC_FILTERS, key );
      *reserr = 1;
      free( filters );
      return NULL;
    }

    strncpy( key, val, sizeof( key ) - 1 );
    key[ sizeof( key ) - 1 ] = '\0';
    if( (val = camconfig_query_str( ccfg, key, "path" )) == NULL ){
      camserv_log( MODNAME, "[%s]:path key/val pair not found in cfg file!",
		   key );
      *reserr = 1;
      free( filters );
      return NULL;
    }

    camserv_log( MODNAME, "Loading filter [%s]", key );

    if( (dlhandle = dlopen( val, RTLD_LAZY | RTLD_GLOBAL )) == NULL ){
      camserv_log( MODNAME, "filter%d: %s", i,  dlerror());
      *reserr = 1;
      free( filters );
      return NULL;
    }

    strncpy( filters[ i ].section_name, key, 
	     sizeof( filters[ i ].section_name ) - 1 );
    filters[ i ].section_name[ sizeof( filters[ i ].section_name ) - 1 ] ='\0';

    if( !(filters[ i ].filter_init = dlsym( dlhandle, "filter_init" ))){
      camserv_log( MODNAME, "filter%d: %s", i, dlerror() );
      dlclose( dlhandle );
      *reserr = 1;
      free( filters );
      return NULL;
    }

    if( !(filters[ i ].filter_deinit = dlsym( dlhandle, "filter_deinit" ))){
      camserv_log( MODNAME, "filter%d: %s", i, dlerror() );
      dlclose( dlhandle );
      *reserr = 1;
      free( filters );
      return NULL;
    }

    if( !(filters[ i ].filter_func = dlsym( dlhandle, "filter_func" ))){
      camserv_log( MODNAME, "filter%d: %s", i, dlerror() );
      dlclose( dlhandle );
      *reserr = 1;
      free( filters );
      return NULL;
    }

    if( !(filters[ i ].modinfo_func = dlsym( dlhandle, "modinfo_query" ))){
      camserv_log( MODNAME, "filter%d: %s", i, dlerror() );
      dlclose( dlhandle );
      *reserr = 1;
      free( filters );
      return NULL;
    }

    filters[ i ].filter_cldat = NULL;
  }

  filters[ nfilters ].filter_init = NULL;  /* Sentinal */

  *reserr = 0;
  return filters;
}

void filter_destroy( Filter *filter_list ){
  free( filter_list );
}
