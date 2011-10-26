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

#include "camserv_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/param.h>

#include "camconfig.h"
#include "camshm.h"
#include "video.h"
#include "sockset.h"
#include "socket.h"
#include "mainloop.h"
#include "picloop.h"
#include "filter.h"
#include "modinfo.h"
#include "log.h"
#include "camserv_hack.h"

static int Shmid;
static int CPid = 0;

#define PICTURE_MALLOC (1024 * 768 * 3)

static 
ModInfo *query_main_modinfo(){
  ModInfo *res;
  char varname[ 1024 ];

  if( (res = modinfo_create( 2 )) == NULL )
    return NULL;

  sprintf( varname, "[%s]:%s", SEC_MAIN, "output_snapfile" );
  modinfo_varname_set( res, 0, varname );
  modinfo_desc_set( res, 0, "Location to place output snapshot" );
  res->vars[ 0 ].type = MODINFO_TYPE_STR;
  
  sprintf( varname, "[%s]:%s", SEC_MAIN, "output_presnaps" );
  modinfo_varname_set( res, 1, varname );
  modinfo_desc_set( res, 1, "# of pictures to take prior to writing output "
		    "(0 disables)" );
  res->vars[ 1 ].type = MODINFO_TYPE_INT;

  return res;
}

static
void dump_cfg_options( CamConfig *ccfg ){
  char vid_section[ 1024 ], key[ 1024 ];
  const char *path, *val;
  ModInfo *minfo;
  int i, nfilters;

  if( video_query_active_section( ccfg, vid_section, sizeof( vid_section ))){
    path = camconfig_query_str( ccfg, vid_section, "path" );
    fprintf( stderr, "*** Module: \"%s\"\n", path );

    if( (minfo = modinfo_query_so( path )) != NULL ){
      modinfo_dump( minfo );
      modinfo_destroy( minfo );
      printf("\n");
    } else
      fprintf( stderr, "Failed to dump video device; \"%s\"\n", path );
  }
  
  nfilters = camconfig_query_def_int( ccfg, SEC_FILTERS, "num_filters", 0 );
  for( i=0; i< nfilters; i++ ){
    sprintf( key, "filter%d_section", i );
    if( (val = camconfig_query_str( ccfg, SEC_FILTERS, key )) == NULL ){
      fprintf( stderr, "KEY/VALUE \"%s\" not found!\n", key );
      continue;
    }
    strncpy( key, val, sizeof( key ) - 1 );
    key[ sizeof( key ) - 1 ] = '\0';
    if( (path = camconfig_query_str( ccfg, key, "path" )) != NULL ){
      if( (minfo = modinfo_query_so( path )) != NULL ){
	fprintf( stderr, "*** Filter: \"%s\"\n", path );
	modinfo_dump( minfo );
	modinfo_destroy( minfo );
	printf("\n");
      } else
	fprintf( stderr, "Failed to dump filter: \"%s\"\n", path );
    }
  }
}

static
CamConfig *read_ccfg( const char *path ){
  FILE *fp;
  CamConfig *res;

  if( (fp = fopen( path, "r" )) == NULL )
    return NULL;

  if( (res = camconfig_read( fp )) == NULL ){
    fclose( fp );
    return NULL;
  }

  fclose( fp );
  return res;
}

/*
 * snap_single:  Take a single snapshot on the camera.  This routine only
 *               verifies if this is the correct course of action for a single
 *               invocation of the camserv binary.  
 *
 * Arguments:    ccfg = Camera configuration 
 *
 * Return values:  Returns 1 if a single snapshot was to occur, else 0
 */

const
int snap_single(CamConfig *ccfg ){
  const char *snapfname;
  int presnaps;

  if( !(snapfname = camconfig_query_str( ccfg, SEC_MAIN, "output_snapfile")))
    return 0;

  presnaps = camconfig_query_def_int( ccfg, SEC_MAIN, "output_presnaps", 0 );
  if( picture_single( ccfg, snapfname, presnaps ) == -1 ){
    camserv_log( "snap_single", "Failed to snap picture!" );
  }
  return 1;
}

    
int main( int argc, char *argv[] ){
  Socket **localsocks;
  CamConfig *camcfg;
  char *shm_segment, tmpbuf[ 1024 ], cfg_path[ MAXPATHLEN ];
  int fd, shm_alloc, donecfg;
  extern int errno;

  donecfg = 0;
  if (argc >= 2) {
    strncpy( cfg_path, argv[ 1 ], sizeof( cfg_path ) );
    cfg_path[ sizeof( cfg_path ) - 1 ] = '\0';
    camserv_log( "main", "Trying to read config file \"%s\": ", cfg_path);
    if( (camcfg = read_ccfg( cfg_path )) == NULL ){
      camserv_log( "main", "Error reading config \"%s\": %s", cfg_path,
		   strerror( errno ));
    } else {
      camserv_log( "main", "Success reading config \"%s\"", cfg_path);
      donecfg=1;
    }
  } else {
    fprintf( stderr, "camserv v%s - by Jon Travis (jtravis@p00p.org)\n", 
	     VERSION );
    fprintf( stderr, "Syntax: %s <cfg file>\n", argv[0] );
    fprintf( stderr, "Will try %s/camserv.cfg\n", DATDIR);
   
    if (!donecfg) {
      snprintf( cfg_path, sizeof( cfg_path ), "%s/camserv.cfg", DATDIR );
      cfg_path[ sizeof( cfg_path ) - 1 ] = '\0';
      camserv_log( "main", "Trying to read config file \"%s\": ", cfg_path);
      if( (camcfg = read_ccfg( cfg_path )) == NULL ){
	camserv_log( "main", "Error reading config \"%s\": %s", cfg_path,
		     strerror( errno ));
      } else {
	camserv_log( "main", "Success reading config \"%s\"", cfg_path);
	donecfg=1;
      }
    }
  }

  if (!donecfg) {
    camserv_log( "main", "Error finding config file, exit!");
    return(-1);
  }

  /* If we took a single snapshot, we are all done */
  if( snap_single( camcfg )) 
    return 0;

  if( (localsocks = socket_unix_pair( SOCK_DGRAM )) == NULL ){
    camserv_log( "main", "Error creating communication sockets between procs");
    return -1;
  }
  
  /* Setup a temp file for making our shm */
  strcpy( tmpbuf, "/tmp/CAMSERV_XXXXXX" );
  if( (fd = mkstemp( tmpbuf )) == -1 ){
    camserv_log( "main", "Couldn't create temporary file: %s", tmpbuf );
    strcpy( tmpbuf, argv[ 0 ] ); /* Last resort */
  } else {
    close( fd );
  }

  shm_alloc = camconfig_query_def_int( camcfg, SEC_MAIN, "shm_alloc", 
				       PICTURE_MALLOC );

  if( shm_alloc < PICTURE_MALLOC )
    camserv_log( "main", "Allocated %d bytes for SHM [RISKY RISKY!]",
		 shm_alloc);

  if( (Shmid = shm_setup( tmpbuf,
			  /* Allocate generous ammount */
			  shm_alloc,
			  &shm_segment) ) == -1 ){

    socket_unix_pair_dest( localsocks );
    return -1;
  }
  unlink( tmpbuf );

/* Start the picture taker thread */
  CPid = picture_taker( shm_segment, PICTURE_MALLOC, camcfg, localsocks[ 0 ]); 
  if( CPid == -1 ){
    /* Failure setting up camerastuffs */
    camserv_log( "main",  "Picture taker could not be created!");
    socket_unix_pair_dest( localsocks );
    return -1;
  }
    
  if( main_loop( camcfg, localsocks[ 1 ], shm_segment ) == -1 ){
    camserv_log( "main", "Main loop exited abnormally");
    socket_unix_pair_dest( localsocks );
    if( CPid != -1 ) kill( CPid, SIGINT );
    return -1;
  }

  socket_unix_pair_dest( localsocks );
  return 0;
}
  
