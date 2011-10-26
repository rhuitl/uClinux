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

/*
 * This module is to provide an example of how to create a new video
 * module for the camserv program. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "grafxmisc.h"
#include "camconfig.h"
#include "modinfo.h"
#include "video.h"

/*
 * In the videodata structure, one should place all of the state information
 * they will need in subsequent callbacks.  This could include a number
 * of things:
 *
 *          o  File descriptors to open video devices.
 *          o  Allocated memory for image storage & manipulation
 *          o  Configuration information about the current state of the device.
 *
 *
 * Keep in mind that ultimately configuration information MUST be read from
 * the camconfig structure so that re-initialization can occur if required.
 * Therefore if something is read from the camcfg structure and then modified,
 * it should be re-written back to the camcfg struct.
 */

typedef struct video_data_st {
  char section_name[ MAX_SECTION_NAME + 1];
  unsigned char components[ 3 ]; /* Rval, gval, and bval                */
  int comp_mod;                  /* Current component being modified    */
  int direction;                 /* Direction of colour changing        */
  int width, height;
  int initialized;               /* 1 if device is initialized, else 0. */
} VideoData;

VideoData *video_open( CamConfig *ccfg, char *section_name );
void video_close( VideoData *vdata );
int video_init( VideoData *vdata, CamConfig *ccfg );
int video_deinit( VideoData *vdata );
int video_snap( VideoData *vdata, char *place_buffer, Video_Info *vinfo,
		CamConfig *ccfg );
int video_get_geom( VideoData *vid_dev, Video_Geometry *geom );

#define DEVICE_MAX_WIDTH  1024
#define DEVICE_MAX_HEIGHT 768
#define DEVICE_MIN_WIDTH  40
#define DEVICE_MIN_HEIGHT 30


/*
 * video_open:  This routine should perform any operations it will need to
 *              do to 'open' and allocate space for device storage.  This
 *              may be things such as opening the device file, allocating
 *              memory for state storage, and initializing states.
 *
 * Arguments:   ccfg = Camera configuration.
 *
 * Return values:  Returns NULL on failure, else a valid pointer to a new
 *                 state structure
 */

VideoData *video_open( CamConfig *ccfg, char *sec_name ){
  VideoData *vdata;

  if( (vdata = malloc( sizeof( *vdata ))) == NULL )
    return NULL;
  
  strncpy( vdata->section_name, sec_name, sizeof( vdata->section_name ));
  vdata->section_name[ sizeof( vdata->section_name ) - 1 ] = '\0';

  vdata->components[ 0 ] = 0;
  vdata->components[ 1 ] = 0;
  vdata->components[ 2 ] = 0;
  vdata->comp_mod = 0;         /* The red component */
  vdata->width = vdata->height = 0;
  vdata->initialized = 0;
  return vdata;
}

/*
 * video_close:  Close a video device, and deallocate all memory associated
 *               with the state information.  At this point, the video module
 *               should consider this to be the final access it has to any
 *               outside thang.
 *
 * Arguments:    vdata = VideoData as returned from the initial video_open.
 */

void video_close( VideoData *vdata ){
  free( vdata );
}

/*
 * video_init:  Initialize the video device.  This is slightly different from
 *              the open routine, in that it may be called often between
 *              an open and close call.  The purpose of this routine is
 *              to use configuration information to configure and 'init'
 *              the device.  This may be called periodically to reconfigure
 *              the video device.  For each init call, there should be 1
 *              de-init call, so the video device need not worry about
 *              init being called twice in a row.
 *
 * Arguments:   ccfg = Camera configuration to use in initialization
 * 
 * Return value:  Returns -1 on failure 0 on success.
 */

int video_init( VideoData *vdata, CamConfig *ccfg ){
  /* Use information from the camconfig structure to init the device */
  /* All of the VIDCONFIG_* settings should be checked and modified as 
   * necessary.  For instance when the device is initialized, if it is
   * black and white, it should be stored in the camconfig structure, as
   * should the actual used width,height, etc. */

  vdata->width  = camconfig_query_def_int( ccfg, SEC_VIDEO,
					   VIDCONFIG_WIDTH, 320 );
  vdata->height = camconfig_query_def_int( ccfg, SEC_VIDEO,
					   VIDCONFIG_HEIGHT, 240 );
  
  vdata->width = clip_to(vdata->width, DEVICE_MIN_WIDTH, DEVICE_MAX_WIDTH);
  vdata->height = clip_to( vdata->height, DEVICE_MIN_HEIGHT,DEVICE_MAX_HEIGHT);

  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_WIDTH,      vdata->width );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_HEIGHT,     vdata->height );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_MAXWIDTH,   DEVICE_MAX_WIDTH );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_MAXHEIGHT,  DEVICE_MAX_HEIGHT );
  camconfig_set_int( ccfg, SEC_VIDEO, 
		     VIDCONFIG_MINWIDTH,   DEVICE_MIN_WIDTH );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_MINHEIGHT,  DEVICE_MIN_HEIGHT );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_ISB_N_W,    0 );
  
  vdata->initialized = 1;
  return 0;
}

/*
 * video_deinit:  De-initialize the video device.  This is to perform
 *                temporary cleanup before a device is either re-initialized
 *                or closed.  This can be used to do things such as freeing
 *                captured video frames, or other cleanup procedures.
 *
 * Arguments:     vdata = Video data as returned from video_open
 * 
 * Return values: Returns -1 on failure, 0 on success.
 */

int video_deinit( VideoData *vdata ){
  return 0;
}


/*
 * video_snap:  Take a 'snapshot' from the video device.  This can range
 *              anywhere from reading device's, generating random noise,
 *              or anything one wants.  The picture taken can be in any
 *              format desired, however when it is placed into the place
 *              buffer it must either be in RGB (1 byte per component)
 *              format, or in the case of B&W a single byte containing the
 *              intensity of the pixel.  The place buffer is provided by
 *              the caller, and will contain enough space to store the
 *              maximum sized output from the snapshot.  In addition, the
 *              vinfo structure should contain information about the size
 *              of the taken picture, and various other attributes, such as
 *              B&W, height, width, etc.
 *
 * Arguments:   vdata        = Video data as returned by video_open.
 *              place_buffer = Location to place output data of the snapshot
 *              vinfo        = Location to place information about the snapshot
 *              ccfg         = Camera configuration to use if necessary.
 *
 * Return values:  Returns 0 on snapshot success, else -1
 */

int video_snap( VideoData *vdata, char *place_buffer, Video_Info *vinfo,
		CamConfig *ccfg )
{
  char *cp, *endcp;

  vinfo->width = vdata->width;
  vinfo->height = vdata->height;
  vinfo->is_black_white = 0;
  vinfo->nbytes = vinfo->width * vinfo->height * 3;

  endcp = place_buffer + vinfo->width * vinfo->height * 3;
  for( cp = place_buffer; cp < endcp; cp += 3 ){
    *(cp + 0) = vdata->components[ 0 ] ;
    *(cp + 1) = vdata->components[ 1 ] ;
    *(cp + 2) = vdata->components[ 2 ] ;
  }

  /* Very simple color changing */
  vdata->components[ vdata->comp_mod ] += vdata->direction *  5;
  if( vdata->components[ vdata->comp_mod ] == 0 ||
      vdata->components[ vdata->comp_mod ] == 255 )
  {  /* Change component */
    vdata->comp_mod = (vdata->comp_mod + 1) % 3;
    if( vdata->components[ vdata->comp_mod ] == 0 )
      vdata->direction = 1;
    else
      vdata->direction = -1;
  }

  return 0;
}

/*
 * video_get_geom:  Get geometry information about the video device. 
 *                  The video device must be opened before the geometry
 *                  can be gotten, so it will be passed in.  All of the
 *                  video device information which CAN be gotten, should.
 *
 * Arguments:       vid_device = Video device as returned from video_open
 *                  geom       = Location to place geometry information
 *
 * Return values:   Returns an ORed combination of VIDEO_GEOM_*, representing
 *                  which information in the returned structure is valid.
 *                  0 is returned on function failure.
 */

int video_get_geom( VideoData *vdata, Video_Geometry *geom ){
  geom->max_width  = DEVICE_MAX_WIDTH;
  geom->max_height = DEVICE_MAX_HEIGHT;
  geom->min_width  = DEVICE_MIN_WIDTH;
  geom->min_height = DEVICE_MIN_HEIGHT;

  if( vdata->initialized == 1 ){
      geom->cur_width  = vdata->width;
      geom->cur_height = vdata->height;
      return VIDEO_GEOM_MAX | VIDEO_GEOM_MIN | VIDEO_GEOM_CUR;
  }      

  return VIDEO_GEOM_MAX | VIDEO_GEOM_MIN;
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
  char varname[ 1024 ];

  if( (res = modinfo_create( 2 )) == NULL )
    return NULL;

  sprintf( varname, "[%s]:%s", SEC_VIDEO, VIDCONFIG_WIDTH );
  modinfo_varname_set( res, 0, varname );
  modinfo_desc_set( res, 0, "Standard video width" );
  res->vars[ 0 ].type = MODINFO_TYPE_INT;
  
  sprintf( varname, "[%s]:%s", SEC_VIDEO, VIDCONFIG_HEIGHT );
  modinfo_varname_set( res, 1, varname );
  modinfo_desc_set( res, 1, "Standard video height" );
  res->vars[ 1 ].type = MODINFO_TYPE_INT;
  
  return res;
}
