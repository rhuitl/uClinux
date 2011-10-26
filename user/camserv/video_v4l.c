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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <math.h>
#include <string.h>

#include <linux/videodev.h>
#include "camserv.h"
#include "video.h"
#include "log.h"
#include "grafxmisc.h"
#include "yuv2rgb.h"

#define SYNC_FAILURE_ALARM 1

#define V4LMOD_DEV_PATH   ( VIDCONFIG_PREFIX "device_path" )
#define V4LMOD_PORT       ( VIDCONFIG_PREFIX "port" )
#define V4LMOD_MODE       ( VIDCONFIG_PREFIX "mode" )
#define V4LMOD_FREQUENCY  ( VIDCONFIG_PREFIX "frequency" )
#define V4LMOD_COLOR      ( VIDCONFIG_PREFIX "color" )
#define V4LMOD_HUE        ( VIDCONFIG_PREFIX "hue" )
#define V4LMOD_CONTRAST   ( VIDCONFIG_PREFIX "contrast" )
#define V4LMOD_BRIGHTNESS ( VIDCONFIG_PREFIX "brightness" )
#define V4LMOD_WHITENESS  ( VIDCONFIG_PREFIX "whiteness" )
#define V4LMOD_AUTOBRIGHT ( VIDCONFIG_PREFIX "autobright" )
#define V4LMOD_BRIGHTMEAN ( VIDCONFIG_PREFIX "brightmean" )
#define V4LMOD_BRIGHTX1   ( VIDCONFIG_PREFIX "brightx1" )
#define V4LMOD_BRIGHTY1   ( VIDCONFIG_PREFIX "brighty1" )
#define V4LMOD_BRIGHTX2   ( VIDCONFIG_PREFIX "brightx2" )
#define V4LMOD_BRIGHTY2   ( VIDCONFIG_PREFIX "brighty2" )
#define V4LMOD_WIDTH      ( VIDCONFIG_WIDTH )
#define V4LMOD_HEIGHT     ( VIDCONFIG_HEIGHT )
#define V4LMOD_MAXWIDTH   ( VIDCONFIG_MAXWIDTH )
#define V4LMOD_MAXHEIGHT  ( VIDCONFIG_MAXHEIGHT )
#define V4LMOD_MINWIDTH   ( VIDCONFIG_MINWIDTH )
#define V4LMOD_MINHEIGHT  ( VIDCONFIG_MINHEIGHT )

#define V4L_DEF_PORT       0
#define V4L_DEF_MODE       VIDEO_MODE_AUTO
#define V4L_DEF_FREQUENCY  0
#define V4L_DEF_COLOR      30000
#define V4L_DEF_HUE        30000
#define V4L_DEF_CONTRAST   30000
#define V4L_DEF_BRIGHTNESS 30000
#define V4L_DEF_WHITENESS  30000
#define V4L_DEF_WIDTH      320
#define V4L_DEF_HEIGHT     240
#define V4L_DEF_AUTOBRIGHT 0
#define V4L_DEF_BRIGHTMEAN 128

#define V4L_BRIGHT_AUTO_INCREMENT     500
#define V4L_BRIGHT_MIN                0
#define V4L_BRIGHT_MAX                60000

#define MODNAME "v4l"

typedef struct video_v4l_st {
  char section_name[ MAX_SECTION_NAME + 1 ];
  struct video_capability vidcaps;
  struct video_window vidwin;
  struct video_tuner vidtuner;
  struct video_channel vidchan;
  struct video_mbuf vidmbuf;
  struct video_mmap vidmmap;
  struct video_audio vidaudio;
  struct video_picture vidpict;

  int current_frame;
  int video_fd;
  char *video_buffer;       /* mmap()ed buffer */ 
  size_t video_buffer_size; /* Size of mmap()ed buffer */
  int initialized;
  int width, height;        /* Width & height of the video */
  int uses_mbuf;
  int is_black_white;       /* TRUE of black and white, else FALSE */

  int autobright;           /* 0 if autobright is turned off, else the #
			       of frames in between brightness adjustments */
  int brightmean;           /* The mean value of the brightness 'goal' when
			       doing autobrightness adjustments */
  int autoleft;             /* # of frames left until next auto bright  */
  int brightx1, brighty1,
      brightx2, brighty2;   /* Points giving rectangle of which to calculate
			       the 'mean' pixel value, which is then used
			       to modify the whole image. */
} Video_V4L;

Video_V4L *video_open( CamConfig *ccfg, char *secname );
void video_close( Video_V4L *v4l_dev );
int video_init( Video_V4L *v4l_dev, CamConfig *ccfg );
int video_deinit( Video_V4L *v4l_dev );
int video_snap( Video_V4L *vid_dev, char *place_buffer, Video_Info *vinfo,
		CamConfig *ccfg );

#define MAX(x,y) ( (x) > (y) ? (x) : (y) )
#define MIN(x,y) ( (x) < (y) ? (x) : (y) )


/*
 * get_camera_parameter:  Given a value for one of the camera pareters,
 *                        clamp it to a valid range, and warn if necessary.
 *
 * Arguments:             val     = Value to get real parameter for
 *                        name    = Associated name of the parameter
 *                        default = Default value of the parameter 
 *                        fromcfg = Don't use 'val' -- instead use the
 *                                  camera configuration. (1==true, 0==false)
 *                        ccfg    = camera configuration.
 *                        secname = Section name owning the camera
 *
 * Return values:         Returns a valid value for the camera.
 */

static
int get_camera_parameter( int val, char *name, int def,
			  int fromcfg, CamConfig *ccfg, char *secname )
{
  if( fromcfg ) val = camconfig_query_def_int( ccfg, secname, name, def );

  if( val < 0 || val > 60000 ){
    camserv_log( MODNAME, "Variable \"%s\" out of range (0->60000)",
		 name );
    if( val < 0 ) return 0;
    if( val > 60000 ) return 60000;
  }
  return val;
}

/*
 * video_set_easy_params:  Set the easy general parameters of hue, colour
 *                         brightness, whiteness, and contrast.  
 *
 * Arguments:              hue, colour, brightness, whiteness, contrast =
 *                             new colours to set.  If the params value is
 *                             < 0, no new value will be set for it.
 *                           
 *                         v4l_dev = V4l device to set params for.
 */

static
void video_set_easy_params( int hue, int colour, int brightness, int whiteness,
			    int contrast, Video_V4L *v4l_dev, CamConfig *ccfg )
{
  if( brightness >= 0 ) {
    v4l_dev->vidpict.brightness = 
      get_camera_parameter( brightness, V4LMOD_BRIGHTNESS, 
			    V4L_DEF_BRIGHTNESS, 0, NULL,v4l_dev->section_name);
    camconfig_set_int( ccfg, v4l_dev->section_name, 
		       V4LMOD_BRIGHTNESS, v4l_dev->vidpict.brightness );
  }

  if( hue >= 0 ){
    v4l_dev->vidpict.hue = 
      get_camera_parameter( hue, V4LMOD_HUE, V4L_DEF_HUE, 0, NULL,
			    v4l_dev->section_name );
    camconfig_set_int( ccfg, v4l_dev->section_name,
		       V4LMOD_HUE, v4l_dev->vidpict.hue );
  }

  if( colour >= 0 ){
    v4l_dev->vidpict.colour = 
      get_camera_parameter( colour, V4LMOD_COLOR, 
			    V4L_DEF_COLOR, 0, NULL, v4l_dev->section_name );
    camconfig_set_int( ccfg, v4l_dev->section_name,
		       V4LMOD_COLOR, v4l_dev->vidpict.colour );
  }

  if( contrast >= 0 ){
    v4l_dev->vidpict.contrast = 
      get_camera_parameter( contrast, V4LMOD_CONTRAST, 
			    V4L_DEF_CONTRAST, 0, NULL, v4l_dev->section_name );
    camconfig_set_int( ccfg, v4l_dev->section_name,
		       V4LMOD_CONTRAST, v4l_dev->vidpict.contrast );
  }

  if( whiteness >= 0 ) {
    v4l_dev->vidpict.whiteness = 
      get_camera_parameter( whiteness, V4LMOD_WHITENESS, 
			    V4L_DEF_WHITENESS, 0, NULL, v4l_dev->section_name);
    camconfig_set_int( ccfg, v4l_dev->section_name,
		       V4LMOD_WHITENESS, v4l_dev->vidpict.whiteness );
  }

  if( ioctl( v4l_dev->video_fd, VIDIOCSPICT, &v4l_dev->vidpict ) == -1 )
    perror( "(V4L) Picture Setting" );

}




/*
 * video_open:  Open the video device file descriptor, allocate
 *              a Video_V4L structure, initialize it, and return it.
 *
 * Arguments:      ccfg = Camera configuration containing the device
 *                        path V4LMOD_DEV_PATH
 *
 * Return valeus:  Returns NULL on failure, else a valid pointer to
 *                 a freshly malloced Video_V4L structure on success.
 */

Video_V4L *video_open( CamConfig *ccfg, char *secname ){
  const char *cfg_device_path;
  Video_V4L *res;
  int fd;

  cfg_device_path = camconfig_query_str( ccfg, secname, V4LMOD_DEV_PATH );
  if( cfg_device_path == NULL ){
    camserv_log( MODNAME, "[%s]:%s unset, defaulting to /dev/video",
	     secname, V4LMOD_DEV_PATH );
    cfg_device_path = "/dev/video";
  }

  if( (fd = open( cfg_device_path, O_RDONLY )) == -1 ){
    perror( "(V4L) video_open" );
    return NULL;
  }

  if( (res = malloc( sizeof( *res ))) == NULL ){
    close( fd );
    return NULL;
  }

  strncpy( res->section_name, secname, sizeof( res->section_name ) - 1 );
  res->section_name[ sizeof( res->section_name ) - 1 ] = '\0';

  res->current_frame     = 0;
  res->video_buffer      = NULL;
  res->video_buffer_size = 0;
  res->video_fd          = fd;
  res->height            = -1;
  res->width             = -1;
  res->initialized       = 0;
  res->is_black_white    = 0;
  res->autobright        = 0;
  res->brightmean        = 0;
  res->autoleft          = 0;
  res->brightx1 = res->brighty1 = res->brightx2 = res->brighty2 = 0;
  return res;
}

/*
 * video_close:  Close the video device, and frees up the entire v4l structure.
 *               No further accesses to this object should be 
 *               made, after it is passed into here.
 *
 * Arguments:    v4l_dev = Video_V4L device previously created by
 *                         calling video_v4l_open
 */

void video_close( Video_V4L *v4l_dev ){
  if( v4l_dev->initialized ){
    if( v4l_dev->video_buffer == NULL )
      camserv_log( MODNAME, "Program inconsistancy! %d %s\n", 
		   __LINE__, __FILE__ );
    if( munmap( v4l_dev->video_buffer, v4l_dev->video_buffer_size ) != 0)
      perror( "(V4L) munmap()" );
  }
  
  close( v4l_dev->video_fd );
  free( v4l_dev );
}


/*
 * setup_video_channel:  Setup the video channel the user has configured
 *                       for.  This can be a little bit tricky, because
 *                       these things aren't easy for the user to setup,
 *                       and we really would like to keep working even
 *                       if all of these fail.
 *
 * Arguments:            v4l_dev = The pre-opened v4l video device
 *                       ccfg    = Camera configuration to configure the
 *                                 video system
 * 
 * Return values:        Returns -1 on failure, 0 on success.
 */

static
int setup_video_channel( Video_V4L *v4l_dev, CamConfig *ccfg ){
  ulong frequency;
  int use_channel;
  int cfg_channel, cfg_frequency, cfg_color, cfg_hue, cfg_contrast,
      cfg_brightness, cfg_whiteness, cfg_norm;

  cfg_channel = camconfig_query_def_int( ccfg, v4l_dev->section_name,
					 V4LMOD_PORT ,V4L_DEF_PORT);
  cfg_norm    = camconfig_query_def_int( ccfg, v4l_dev->section_name,
					 V4LMOD_MODE, V4L_DEF_MODE );
  cfg_frequency = camconfig_query_def_int( ccfg, v4l_dev->section_name,
					   V4LMOD_FREQUENCY,V4L_DEF_FREQUENCY);
  cfg_color = get_camera_parameter( 0, V4LMOD_COLOR, V4L_DEF_COLOR,
				    1, ccfg, v4l_dev->section_name );
  cfg_hue   = get_camera_parameter( 0, V4LMOD_HUE, V4L_DEF_HUE,
				    1, ccfg, v4l_dev->section_name );
  cfg_contrast = get_camera_parameter( 0, V4LMOD_CONTRAST, V4L_DEF_CONTRAST, 
				       1, ccfg, v4l_dev->section_name );
  cfg_brightness = get_camera_parameter( 0, V4LMOD_BRIGHTNESS, 
					 V4L_DEF_BRIGHTNESS, 1, ccfg,
					 v4l_dev->section_name );
  cfg_whiteness = get_camera_parameter( 0, V4LMOD_WHITENESS, 
					V4L_DEF_WHITENESS, 1, ccfg,
					v4l_dev->section_name );
  v4l_dev->autobright = camconfig_query_def_int( ccfg, v4l_dev->section_name,
						 V4LMOD_AUTOBRIGHT,
						 V4L_DEF_AUTOBRIGHT );
  if( v4l_dev->autobright ) {
    int newmean, x1, y1, x2, y2;
    v4l_dev->brightmean = camconfig_query_def_int( ccfg, v4l_dev->section_name,
						   V4LMOD_BRIGHTMEAN,
						   V4L_DEF_BRIGHTMEAN );
    newmean = clip_to(v4l_dev->brightmean, 0, 255 );
    if( v4l_dev->brightmean != newmean  ){
      camserv_log( MODNAME, "%s clamped to a value of %d (0-255)",
		   V4LMOD_BRIGHTMEAN, newmean );
      v4l_dev->brightmean = newmean;
    }

    x1 = camconfig_query_def_int(ccfg,v4l_dev->section_name,V4LMOD_BRIGHTX1,0);
    y1 = camconfig_query_def_int(ccfg,v4l_dev->section_name,V4LMOD_BRIGHTY1,0);
    x2 = camconfig_query_def_int(ccfg,v4l_dev->section_name,V4LMOD_BRIGHTX2,0);
    y2 = camconfig_query_def_int(ccfg,v4l_dev->section_name,V4LMOD_BRIGHTY2,0);
    
    v4l_dev->brightx1 = clip_to(x1, 0, v4l_dev->width);
    v4l_dev->brighty1 = clip_to(y1, 0, v4l_dev->height);
    v4l_dev->brightx2 = clip_to(x2, 0, v4l_dev->width);
    v4l_dev->brighty2 = clip_to(y2, 0, v4l_dev->height);
    if( v4l_dev->brightx2 < v4l_dev->brightx1 ||
	v4l_dev->brighty2 < v4l_dev->brighty1 ){
      camserv_log( MODNAME, "Disabling autobrightness!  (reversed coords)");
      v4l_dev->autobright = 0;
    }
  }
      
  if( v4l_dev->autobright < 0 ) v4l_dev->autobright = 0;
  if( v4l_dev->autobright ) v4l_dev->autoleft = 1;
  
  /* First setup the channel that user requested .. maybe a tunable
     port .. might not be */
  if( cfg_channel >= v4l_dev->vidcaps.channels ){
    v4l_dev->vidchan.channel = 0;
    if( ioctl( v4l_dev->video_fd, VIDIOCGCHAN, &v4l_dev->vidchan) == -1 ){
      camserv_log( MODNAME, "Invalid input port requested (%d), resorting to "
		   "port 0 (Unknown)", cfg_channel);
    } else {
      camserv_log( MODNAME, "Invalid input port requested (%d), resorting to "
		   "port 0 (%s)", cfg_channel, v4l_dev->vidchan.name );
    }
    use_channel = 0;
  } else 
    use_channel = cfg_channel;

  v4l_dev->vidchan.channel = use_channel; /* Apparently broken in Gnoghurt */
  if( ioctl (v4l_dev->video_fd, VIDIOCGCHAN, &v4l_dev->vidchan) == -1 ){
    perror( "(V4L) Channel-get IOCTL" );
    return -1;
  }

  /* Setup the video norm to use.  Detection of the norm-setting capability of
     a channel via VIDEO_VC_NORM isn't available in all versions of V4l */
#ifdef VIDEO_VC_NORM
  if( v4l_dev->vidchan.flags & VIDEO_VC_NORM ) {
#endif
    v4l_dev->vidchan.channel = use_channel;
    v4l_dev->vidchan.norm = cfg_norm;
    if( ioctl( v4l_dev->video_fd, VIDIOCSCHAN, &v4l_dev->vidchan ) == -1 ){
      camserv_log( MODNAME, "Unable to set video NORM (picture may be wrong)");
      perror( "(V4L) VIDIOCSCHAN" );
      /* Excusable error */
    }
#ifdef VIDEO_VC_NORM
  } else
    camserv_log( MODNAME, "Channel can't set norm." );
#endif



  /* If this channel is tunable, then we need to go ahead and
     set the frequency */
  if(cfg_frequency != 0){
    if(!(v4l_dev->vidchan.flags & VIDEO_VC_TUNER) ){
      camserv_log( MODNAME, "Invalid frequency!  (Channel has no tuner!)" );
    } else {
      frequency = cfg_frequency * 16;
      if( ioctl (v4l_dev->video_fd, VIDIOCSFREQ, &frequency ) == -1 ){
	perror( "(V4L) Frequency Setting" );
	/* Excusable error */
      }
    }
  }

#if 0
  /* This audio stuff really doesn't work ATM */
  if( !(v4l_dev->vidchan.flags & VIDEO_VC_AUDIO) &&
      vparams->volume != -1 ){
    camserv_log( MODNAME, "Invalid volume!  (Channel has no volume!)");
  } else {
    v4l_dev->vidaudio.audio = 0;
    v4l_dev->vidaudio.flags = 0;
    v4l_dev->vidaudio.mode  = VIDEO_SOUND_STEREO;
    if( ioctl( v4l_dev->video_fd, VIDIOCSAUDIO, &v4l_dev->vidaudio ) == -1 ){
      perror( "Audio Setting" );
    }
  }
#endif
  /* Setup the colors, etc */
  if( ioctl( v4l_dev->video_fd, VIDIOCGPICT, &v4l_dev->vidpict ) == -1 ){
    perror( "(V4L) Picture Getting" );
  } else {
    if( v4l_dev->vidpict.palette == VIDEO_PALETTE_GREY ){
      v4l_dev->is_black_white = 1;
      camserv_log( MODNAME, "Detected black and white camera");
    } else
      v4l_dev->is_black_white = 0;

    video_set_easy_params( cfg_hue, cfg_color, cfg_brightness, cfg_whiteness,
			   cfg_contrast, v4l_dev, ccfg );
  }
  return 0;
}

static
void v4l_alarm_handler( int sig ){
  camserv_log( MODNAME, "Sync alarm called!");
}

/*
 * video_v4l_initialize:  Initialize the video camera.  This routine
 *                        will query the video device for the 
 *                        capabilities, and select the optimal properties
 *                        for the given parameters.  
 *
 * Arguments:             v4l_dev = valid Video_V4L object. 
 *                        ccfg    = Parameters to initialize the device with
 *
 * Return Value:     Returns -1 on failure, else 0
 */

int video_init( Video_V4L *v4l_dev, CamConfig *ccfg ){
  int cfg_width, cfg_height;
  int i;

  if( v4l_dev->initialized == 1 )
    if( video_deinit( v4l_dev ) == -1 )
      return -1;

  if( ioctl( v4l_dev->video_fd, VIDIOCGCAP, &v4l_dev->vidcaps ) == -1 ||
      ioctl( v4l_dev->video_fd, VIDIOCGWIN, &v4l_dev->vidwin ) == -1 )
  {
    perror( "(V4L) GCAP && GWIN" );
    return -1;
  }

  v4l_dev->vidwin.x = 0;
  v4l_dev->vidwin.y = 0;
  cfg_width  = camconfig_query_def_int( ccfg, SEC_VIDEO,
					V4LMOD_WIDTH, V4L_DEF_WIDTH );
  cfg_height = camconfig_query_def_int( ccfg, SEC_VIDEO,
					V4LMOD_HEIGHT, V4L_DEF_HEIGHT );
  
  v4l_dev->vidwin.width = clip_to(cfg_width, v4l_dev->vidcaps.minwidth,
                                  v4l_dev->vidcaps.maxwidth );
  v4l_dev->vidwin.height = clip_to(cfg_height, v4l_dev->vidcaps.minheight, 
                                   v4l_dev->vidcaps.maxheight);

  v4l_dev->vidwin.clipcount = 0;
  v4l_dev->vidwin.flags = 0;

  if( ioctl (v4l_dev->video_fd, VIDIOCSWIN, &v4l_dev->vidwin) == -1 ||
      ioctl( v4l_dev->video_fd, VIDIOCGWIN, &v4l_dev->vidwin) == -1)
  {
    perror( "(V4L) Video IOCTL" );
    return -1;
  }

  camserv_log("video_init","image width: default:%d max:%d min:%d config:%d used:%d\n",
        V4L_DEF_WIDTH, v4l_dev->vidcaps.maxwidth, v4l_dev->vidcaps.minwidth,
        cfg_width, v4l_dev->vidwin.width);
  camserv_log("video_init","image height: default:%d max:%d min:%d config:%d used:%d\n",
        V4L_DEF_HEIGHT, v4l_dev->vidcaps.maxheight, v4l_dev->vidcaps.minheight,
        cfg_height, v4l_dev->vidwin.height);

  v4l_dev->width = v4l_dev->vidwin.width;
  v4l_dev->height = v4l_dev->vidwin.height;

  if( setup_video_channel( v4l_dev, ccfg ) == -1 )
    return -1;

  if( ioctl (v4l_dev->video_fd, VIDIOCGMBUF, &v4l_dev->vidmbuf) == -1 ){
    camserv_log( MODNAME, "Coulnd't use VIDIOCGMBUF -- assuming non bttv");
    v4l_dev->uses_mbuf = 0;
  } else {
    v4l_dev->video_buffer_size = v4l_dev->vidmbuf.size;
    v4l_dev->video_buffer = mmap( 0, v4l_dev->video_buffer_size,
				  PROT_READ, MAP_SHARED, 
				  v4l_dev->video_fd, 0);
    if( v4l_dev->video_buffer == (void *)-1 ){
      perror( "(V4L) mmap" );
      return -1;
    }
  
    v4l_dev->vidmmap.height = v4l_dev->height;
    v4l_dev->vidmmap.width = v4l_dev->width;

    if(ioctl(v4l_dev->video_fd, VIDIOCGPICT, &v4l_dev->vidpict) == -1){
      perror("(V4L) Picture capabilities fetch");
      return -1;
    } else {
      if(v4l_dev->vidpict.palette == VIDEO_PALETTE_YUV420P){
	v4l_dev->vidmmap.format = VIDEO_PALETTE_YUV420P;
	yuv2rgb_init();
      } else {
	v4l_dev->vidmmap.format = VIDEO_PALETTE_RGB24;
      }
    }
    v4l_dev->current_frame = 0;
  
    for( i=0; i< v4l_dev->vidmbuf.frames; i++ ){
      v4l_dev->vidmmap.frame = i;
      if(ioctl(v4l_dev->video_fd, VIDIOCMCAPTURE, &v4l_dev->vidmmap ) == -1 ) {
        camserv_log( MODNAME, "Failed with RGB, trying YUV420P");
        v4l_dev->vidmmap.format = VIDEO_PALETTE_YUV420P;

        if(ioctl(v4l_dev->video_fd, VIDIOCMCAPTURE, &v4l_dev->vidmmap ) == -1 )
          perror( "(V4L) Filling capture frames" );
      }
    }
    v4l_dev->vidmmap.frame = 0;
    v4l_dev->uses_mbuf = 1;
  }

  /* Setup configuration entries so that the filters, etc, can use the
     information */
  camconfig_set_int( ccfg, SEC_VIDEO,
		     V4LMOD_WIDTH, v4l_dev->width );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     V4LMOD_HEIGHT, v4l_dev->height );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     V4LMOD_MAXWIDTH, v4l_dev->vidcaps.maxwidth );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     V4LMOD_MAXHEIGHT, v4l_dev->vidcaps.maxheight );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     V4LMOD_MINWIDTH, v4l_dev->vidcaps.minwidth );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     V4LMOD_MINHEIGHT, v4l_dev->vidcaps.minheight );
  camconfig_set_int( ccfg, SEC_VIDEO,
		     VIDCONFIG_ISB_N_W, v4l_dev->is_black_white );

  if( signal( SIGALRM, v4l_alarm_handler ) == SIG_ERR ) {
    camserv_log( MODNAME, "Could not set alarm handler.  "
		 "Things may not work correctly!");
  }

  v4l_dev->initialized = 1;
  return 0;
}

/*
 * video_deinit:  Deinitialize a v4l device.  This clears up captured
 *                frames and the buffers used for storage .. This should
 *                be done everytime the camera is to be re-configured,
 *                (for every init call)
 *
 * Arguments:     v4l_dev = Device to deinitialize
 *
 * Return values:  Returns -1 on error, 0 on success.
 */

int video_deinit( Video_V4L *v4l_dev ){
  int i;

  if( v4l_dev->initialized == 0 ){
    camserv_log( MODNAME, "Deinitialized without initializing V4L device\n");
    return -1;
  }

  if( v4l_dev->uses_mbuf == 1 ){
    /* Clear up the allocated pictures we have already taken */
    for( i=0; i< v4l_dev->vidmbuf.frames; i++ ){
      alarm( SYNC_FAILURE_ALARM );
      if( ioctl( v4l_dev->video_fd, VIDIOCSYNC, &i ) == -1 )
	perror( "(V4L) Freeing captured frames" );
      alarm( 0 );
    }

    if( munmap( v4l_dev->video_buffer, v4l_dev->video_buffer_size ) != 0 )
      perror( "(V4L) video_4l_deinitialize: munmap" );
  }    

  v4l_dev->width = v4l_dev->height = -1;
  v4l_dev->current_frame = 0;

  v4l_dev->video_buffer = NULL;
  v4l_dev->video_buffer_size = 0;
  v4l_dev->initialized = 0;

  return 0;
}

/*
 * adjust_bright:  Adjust the brightness of an image.  If the image
 *                 has a mean pixel value outside of a small range of
 *                 the middle, the picture brightness level is slightly
 *                 tweaked to attempt to balance it out.
 *                    
 * Arguments:      width, height = Dimensons of the picture.
 *                 addr    = address of the picture
 *                 is_rgb  = 1 if the pic is rgb, else 0
 *                 v4l_dev = V4l dev.
 *                 ccfg    = Camera configuration to hold new values
 *                               of the brightness when it is adjusted.
 *
 * Return values:  Returns 1 if an adjustment was made, else 0
 */

static int
adjust_bright( int width, int height, const char *addr, int is_rgb,
		       Video_V4L *v4l_dev, CamConfig *ccfg  )
{
  int totmean, newbright;
  int adjust;

  if( !v4l_dev->autobright || 
      --v4l_dev->autoleft > 0 ) 
    return 0;

  totmean = camserv_get_pic_mean( width, height, addr, is_rgb, 0, 0,
				  width, height );
  adjust = 0;

  if( totmean < v4l_dev->brightmean - 10 || 
      totmean > v4l_dev->brightmean + 10 ){

    newbright = v4l_dev->vidpict.brightness;
    if( totmean > v4l_dev->brightmean) 
      newbright -= V4L_BRIGHT_AUTO_INCREMENT;
    else
      newbright += V4L_BRIGHT_AUTO_INCREMENT;
    newbright = clip_to(newbright, V4L_BRIGHT_MIN, V4L_BRIGHT_MAX);
    adjust = 1;
  }

  if( adjust ){
    /* Slight adjustment */
    video_set_easy_params( -1, -1, 
			   newbright,
			   -1, 
			   -1, v4l_dev, ccfg );
    return 1;
  } else {
    v4l_dev->autoleft = v4l_dev->autobright;
    return 0;
  }
}


/* 
   functions ripped from xawtv source (v3.56): libng/color_yuv2rgb.c
   and slightly modified
*/

/* name in xawtv source: ng_color_yuv2rgb_init() */
static void yuv2rgb_init(void){
    int i;
    
    /* init Lookup tables */
    for (i = 0; i < 256; i++) {
        ng_yuv_gray[i] = i * LUN_MUL >> 8;
        ng_yuv_red[i]  = (RED_ADD    + i * RED_MUL)    >> 8;
        ng_yuv_blue[i] = (BLUE_ADD   + i * BLUE_MUL)   >> 8;
        ng_yuv_g1[i]   = (GREEN1_ADD + i * GREEN1_MUL) >> 8;
        ng_yuv_g2[i]   = (GREEN2_ADD + i * GREEN2_MUL) >> 8;
    }
    for (i = 0; i < CLIP; i++)
        ng_clip[i] = 0;
    for (; i < CLIP + 256; i++)
        ng_clip[i] = i - CLIP;
    for (; i < 2 * CLIP + 256; i++)
        ng_clip[i] = 255;
}

/* name in xawtv source: yuv420p_to_rgb24() */
static void   
yuv2rgb (char *out_addr, char *in_addr, int rowstride, int width, int height)
{
    unsigned char *y,*u,*v;
    unsigned char *us,*vs;
    unsigned char *dp,*d;
    int i,j,gray;

    dp = (unsigned char *)out_addr;
    y  = (unsigned char *)in_addr;
    u  = y + width * height;
    v  = u + width * height / 4;

    for (i = 0; i < height; i++) {
        d = dp;
        us = u; vs = v;
        for (j = 0; j < width; j+= 2) {
            gray   = GRAY(*y);
            *(d++) = RED(gray,*v);
            *(d++) = GREEN(gray,*v,*u);
            *(d++) = BLUE(gray,*u);
            y++;
            gray   = GRAY(*y);
            *(d++) = RED(gray,*v);
            *(d++) = GREEN(gray,*v,*u);
            *(d++) = BLUE(gray,*u);
            y++; u++; v++;
        }
        if (0 == (i % 2)) {
            u = us; v = vs;
        }
        dp += rowstride;
    }
}

static void
bgr2rgb (char *out_addr, char *in_addr, int rowstride, int width, int height)
{
  int i, j;

  for (i=0; i<height; i++){
    char *q = out_addr + i * rowstride;
    char *p = in_addr + i * rowstride;
    
    for (j=0; j<width; j++)
      {
	q[2] = p[0];
	q[1] = p[1];
	q[0] = p[2];
	
	q += 3;
	p += 3;
      }
  }

}

static
int mbuf_snapshot( Video_V4L *vid_dev, char *place_buffer ){
  /* XXX -- Apparently the v4linux stuff can sometimes hang on a
     VIDIOCSYNC call .. *sigh* -- SO we simply bail out when the
     alarm rings */

  alarm( SYNC_FAILURE_ALARM );
  if( ioctl( vid_dev->video_fd, VIDIOCSYNC, &vid_dev->current_frame) == -1 ){
    perror( "VIDIOSYNC" );
    return -1;
  }
  alarm( 0 );

  if(vid_dev->vidmmap.format == VIDEO_PALETTE_YUV420P){
      yuv2rgb( place_buffer,
	       vid_dev->video_buffer + 
	       vid_dev->vidmbuf.offsets[ vid_dev->current_frame ],
	       vid_dev->width * 3, vid_dev->width, vid_dev->height );
  } else {
      bgr2rgb( place_buffer,
	       vid_dev->video_buffer + 
	       vid_dev->vidmbuf.offsets[ vid_dev->current_frame ],
	       vid_dev->width * 3, vid_dev->width, vid_dev->height );
  }

  if( ioctl( vid_dev->video_fd, VIDIOCMCAPTURE, &vid_dev->vidmmap ) == -1 ){
    perror( "VIDIOCMCAPTURE" );
    /* Increment current frame information anyway, since the SYNC occurred 
       XXX */
#if 0
    vid_dev->current_frame =(vid_dev->current_frame+1)%vid_dev->vidmbuf.frames;
    vid_dev->vidmmap.frame = vid_dev->current_frame;
#endif
    return -1;
  }

  vid_dev->current_frame = (vid_dev->current_frame+1)%vid_dev->vidmbuf.frames;
  vid_dev->vidmmap.frame = vid_dev->current_frame;

  return 0;
}

/*
 * video_snap:  Take a snapshot from the video device, and put it into
 *              place_buffer.  The format is a RGB format, and place_buffer
 *              is expected to contain enough space to store the 
 *              width * height * 3 bytes
 *
 * Arguments:   vid_dev = Video device to snap the picture of
 *              place_buffer = Storage location to put the picture
 *              vinfo = Storage location for information about the picture
 *                      snapped.
 *
 * Return values:  Returns -1 on error, 0 on success.
 */

int video_snap( Video_V4L *vid_dev, char *place_buffer, Video_Info *vinfo,
		CamConfig *ccfg ){
  int size, res;

  if( vid_dev->is_black_white )
    size = vid_dev->width * vid_dev->height;
  else
    size = vid_dev->width * vid_dev->height * 3;

  vinfo->width = vid_dev->width;
  vinfo->height = vid_dev->height;
  vinfo->is_black_white = vid_dev->is_black_white;
  vinfo->nbytes = size;

  if( vid_dev->uses_mbuf == 1 ) {
    res = mbuf_snapshot( vid_dev, place_buffer );
    if( res == -1 ) return -1;
    adjust_bright( vid_dev->width, vid_dev->height, place_buffer,
		   !vinfo->is_black_white, vid_dev, ccfg );
    return res;
  }

  if( read( vid_dev->video_fd, place_buffer, size ) != size ){
    perror( "(V4L) snapshot read()" );
    return -1;
  }

  
  adjust_bright( vid_dev->width, vid_dev->height, place_buffer,
		 !vinfo->is_black_white, vid_dev, ccfg );
  
  return 0;
}

/*
 * video_get_geom:  Get geometry information about the video device. 
 *                  The video device must be opened before the geometry
 *                  can be gotten.  
 *
 * Arguments:       vid_device = Video device as from video_open
 *                  geom       = Location to place geometry information
 *
 * Return values:   Returns an ORed combination of VIDEO_GEOM_*, representing
 *                  which information in the returned structure is valid.
 *                  0 is returned on function failure.
 */

int video_get_geom( Video_V4L *vid_dev, Video_Geometry *geom ){
  int got_cur = 1;

  if( vid_dev->initialized == 0 ){
    if( ioctl( vid_dev->video_fd, VIDIOCGCAP, &vid_dev->vidcaps ) == -1 )
      return 0;

    got_cur = 1;
  }

  geom->max_width = vid_dev->vidcaps.maxwidth;
  geom->max_height = vid_dev->vidcaps.maxheight;
  geom->min_width = vid_dev->vidcaps.minwidth;
  geom->min_height = vid_dev->vidcaps.minheight;
  
  if( got_cur == 1 ) {
    geom->cur_width = vid_dev->width;
    geom->cur_height = vid_dev->height;
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

  if( (res = modinfo_create( 16 )) == NULL )
    return NULL;

  sprintf( varname, "[%s]:%s", SEC_VIDEO, VIDCONFIG_WIDTH );
  modinfo_varname_set( res, 0, varname );
  modinfo_desc_set( res, 0, "Standard video width" );
  res->vars[ 0 ].type = MODINFO_TYPE_INT;
  
  sprintf( varname, "[%s]:%s", SEC_VIDEO, VIDCONFIG_HEIGHT );
  modinfo_varname_set( res, 1, varname );
  modinfo_desc_set( res, 1, "Standard video height" );
  res->vars[ 1 ].type = MODINFO_TYPE_INT;
  
  modinfo_varname_set( res, 2, V4LMOD_BRIGHTNESS );
  modinfo_desc_set( res, 2, "Video Brightness (0->60000)" );
  res->vars[ 2 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 3, V4LMOD_HUE );
  modinfo_desc_set( res, 3, "Video Hue (0->60000)" );
  res->vars[ 3 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 4, V4LMOD_COLOR );
  modinfo_desc_set( res, 4, "Video Color (0->60000)" );
  res->vars[ 4 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 5, V4LMOD_CONTRAST );
  modinfo_desc_set( res, 5, "Video Contrast (0->60000)" );
  res->vars[ 5 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 6, V4LMOD_WHITENESS );
  modinfo_desc_set( res, 6, "Video Whiteness (0->60000)" );
  res->vars[ 6 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 7, V4LMOD_PORT );
  modinfo_desc_set( res, 7, "Video Input Port" );
  res->vars[ 7 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 8, V4LMOD_FREQUENCY );
  modinfo_desc_set( res, 8, "Video Tuner Frequency" );
  res->vars[ 8 ].type = MODINFO_TYPE_FLOAT;

  modinfo_varname_set( res, 9, V4LMOD_AUTOBRIGHT );
  modinfo_desc_set( res, 9, "Video Autobrightness Setting (0 disables, else "
		    "# of frames between fixes" );
  res->vars[ 9 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 10, V4LMOD_BRIGHTMEAN );
  modinfo_desc_set( res, 10, "Video Brightness Mean -- Average value of pixel "
		    "(0->255)" );
  res->vars[ 10 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 11, V4LMOD_BRIGHTX1 );
  modinfo_desc_set( res, 11, "Top left corner of brightness detect rectangle");
  res->vars[ 11 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 12, V4LMOD_BRIGHTY1 );
  modinfo_desc_set( res, 12, "Top left corner of brightness detect rectangle");
  res->vars[ 12 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 13, V4LMOD_BRIGHTX2 );
  modinfo_desc_set( res, 13, "Bottom right corner of brightness detect "
		    "rectangle" );
  res->vars[ 13 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 14, V4LMOD_BRIGHTY2 );
  modinfo_desc_set( res, 14, "Bottom right corner of brightness detect "
		    "rectangle" );
  res->vars[ 14 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 15, V4LMOD_BRIGHTNESS );
  modinfo_desc_set( res, 15, "Video mode (PAL, etc) (0->3)" );
  res->vars[ 15 ].type = MODINFO_TYPE_INT;

  return res;
}
