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
#include "video.h"


#define MODNAME "video"

/*
 * video_query_active_section: Query the active video section in the
 *                             camconfig.
 *
 * Arguments:                  ccfg  = Camera configuration
 *                             place = Location to place the section name
 *                             size  = Size of memory @ place
 *
 * Return values:              Returns NULL on failure, else a valid ptr
 *                             to 'place'
 */

char *video_query_active_section( CamConfig *ccfg, char *place, int size){
  const char *val;

  val = camconfig_query_str( ccfg, SEC_VIDEO, "video_section" );
  if( val == NULL ){
    camserv_log( MODNAME, "[%s]:video_section has not been set!",
		 SEC_VIDEO );
    return NULL;
  }

  strncpy( place, val, size - 1 );
  place[ size - 1 ] = '\0';
  return place;
}

/*
 * video_setup_funcs:  Open the video module, and fill out the structure
 *                     with all of the video accessing routines.
 *                     
 * Arguments:          ccfg = Camera configuration structure which
 *                            should contain VIDCONFIG_PATH which holds
 *                            the location for the video module.
 *                     vfuncs = Structure to place all of the video functions
 *                              as they are grabbed from the symbol table.
 *
 * Return values:      Returns -1 on failure (if the module could not be
 *                     opened, or a symbol could not be found), 0 on success.
 */

int video_setup_funcs( CamConfig *ccfg, Video_Funcs *vfuncs ){
  void *dlhandle;
  char key[ 1024 ];
  const char *module_path;

  if( video_query_active_section( ccfg, key, sizeof( key )) == NULL )
    return -1;

  if( (module_path = camconfig_query_str( ccfg, key, "path" )) == NULL ){
    camserv_log( MODNAME, "[%s]:path not set!", key );
    return -1;
  }

  if( (dlhandle = dlopen( module_path, RTLD_LAZY | RTLD_GLOBAL )) == NULL ){
    camserv_log( MODNAME, "%s", dlerror());
    camserv_log( MODNAME, "Error opening video driver; \"%s\"", module_path );
    return -1;
  }

  if( !(vfuncs->video_open = dlsym( dlhandle, VIDSYM_OPEN ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  if( !(vfuncs->video_close = dlsym( dlhandle, VIDSYM_CLOSE ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  if( !(vfuncs->video_init = dlsym( dlhandle, VIDSYM_INIT ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  if( !(vfuncs->video_deinit = dlsym( dlhandle, VIDSYM_DEINIT ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  if( !(vfuncs->video_snap = dlsym( dlhandle, VIDSYM_SNAP ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  if( !(vfuncs->video_get_geom = dlsym( dlhandle, VIDSYM_GET_GEOM ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  if( !(vfuncs->video_modinfo_query = dlsym( dlhandle, VIDSYM_MODINFO ))){
    camserv_log( MODNAME, dlerror() );
    dlclose( dlhandle );
    return -1;
  }

  return 0;
}
