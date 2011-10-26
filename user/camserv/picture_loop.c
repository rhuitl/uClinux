#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <signal.h>

#include "camserv.h"
#include "camconfig.h"
#include "camshm.h"
#include "video.h"
#include "sockset.h"
#include "socket.h"
#include "log.h"
#include "picloop.h"
#include "filter.h"

#define MAX_CONSEC_BAD_SNAPS 5  /* Maximum # of consecutive bad snaps allowed*/
#define DEFAULT_MAX_FPS      0

static int initialized = 0;
static int Abort = 0;

#define MODNAME "picloop"

/*
 * report_picsnap:  Report a snapped picture to the parent process.  
 *
 * Arguments:       server_sock = Socket connection to the parent
 *                  bytes       = # of bytes of the picture just snapped.
 */

static
void report_picsnap( Socket *server_sock, int bytes ){
  char buf[ 1024 ];
  
  sprintf( buf, "%d %d", 0, bytes );
  send( socket_query_fd( server_sock ),
	buf, strlen( buf ) + 1, 0 );
}

/*
 * init_taker:  Initialize the video device and all of the filters.  
 *              
 * Arguments:   vfuncs  = Pointers to valid video functions
 *              filters = List of filters as returned by filter_setup
 *              vid_device = Vid device as returned by video_open 
 *              camconfig = Current camera configuration
 *              memhack_buf = Location to store memhack_buf if it exists.
 *                           if the camconfig specifies that memhackery is
 *                           to be used, *memhack_buf will be a valid pointer
 *                           on return, else NULL
 *              max_fps     = Location to store max FPS as returned from ccfg
 *              do_memhack  = if 1 setup memhack_buf if appropriate, else dont
 *
 * Return values:  Returns -1 on failure, 0 on success.
 */

static
int init_taker( Video_Funcs *vfuncs, Filter *filters, void *vid_device,
		CamConfig *camconfig, char **memhack_buf, float *max_fps,
		int do_memhack_buf )
{
  Video_Geometry geom;
  int gres;

  if( initialized ) 
    camserv_log( MODNAME, "BOGUS INIT TAKER DOUBLE INITIALIZATION!");

  if( vfuncs->video_init( vid_device, camconfig ) == -1 ){
    camserv_log( MODNAME, "Failed to initialize video device!");
    return -1;
  }

  gres = vfuncs->video_get_geom( vid_device, &geom );
  if( !(gres & VIDEO_GEOM_CUR)){
    camserv_log( MODNAME, "Failed to get current geometry information");
    vfuncs->video_deinit( vid_device );
    return -1;
  }
  
  if( do_memhack_buf == 1 ){
    if( camconfig_query_def_int( camconfig, SEC_VIDEO,
				 "memhack", 1 ) == 1)
    {
      *memhack_buf = malloc( geom.cur_width * geom.cur_height * 3 );
      if( *memhack_buf == NULL ){
	camserv_log( MODNAME, "Error allocating memhack buffer!");
	return -1;
      }
    } else {
      *memhack_buf = NULL;
    }
  }
  *max_fps = camconfig_query_def_float( camconfig, SEC_VIDEO,
					"maxfps", DEFAULT_MAX_FPS );
  filter_list_init( filters, camconfig );
  initialized = 1;
  return 0;
}


/*
 * deinit_taker:  Deinitialize the video device, and all of the filters, as
 *                well as free up the memhack buffer if it was previously
 *                allocated.
 *
 * Arguments:     Same as in init_taker.
 */

static
void deinit_taker( Video_Funcs *vfuncs, Filter *filters, void *vid_device,
		   CamConfig *camconfig, char *memhack_buf )
{
  if( !initialized ) {
    camserv_log( MODNAME, "BOGUS DEINIT CALL IN PICTURE TAKER!");
  }

  if( vfuncs->video_deinit( vid_device ) == -1 ) 
    camserv_log( MODNAME, "Could not de-initialize video device!");

  if( memhack_buf != NULL )
    free( memhack_buf );

  filter_list_deinit( filters );
  initialized = 0;
}    

/*
 * sleep_abit:  Sleep for a little while to come close to our max_fps
 *              setting.  This isn't exact, but it is decent enough
 *
 * Arguments:   cur_fps = The current fps 
 *              max_fps = The camconfig max_fps setting.
 */

static
void sleep_abit( float cur_fps, float max_fps )
{
  float diff;
  unsigned long msex;

  /* we don't want to make a huge chunk in the frame rate if the camera
     is going way to fast.  So we amortize it out over a few frames.  This
     isn't the greatest but it appears to work decently */

  if( cur_fps <= max_fps ) return;

  diff = cur_fps - max_fps;
  msex = (diff / max_fps) * 1000000;
  if( max_fps > .3 && msex / 1000000 > 3 ) msex = 3 * 1000000;

  sleep( msex / 1000000 );
  usleep( msex % 1000000 );
}

/*
 * open_taker:  Open the video taker & initialize the vfuncs for accessing it.
 *
 * Arguments:   ccfg   = Camera cfg denoting where the device is.
 *              place_vfuncs = Location to place vfuncs to access the device
 *              place_filters = Location to place filter information.
 *
 * Return values:  Returns NULL on failure, else a pointer to the valid
 *                 video device.
 */

static
void *open_taker( CamConfig *ccfg, Video_Funcs *place_vfuncs,
		  Filter **place_filters )
{
  char vidsec[ 1024 ];
  void *vid_res;
  Filter *filters;
  int eres;

  if( video_query_active_section( ccfg, vidsec, sizeof( vidsec )) == NULL )
    return NULL;

  if( video_setup_funcs( ccfg, place_vfuncs ) == -1 )
    return NULL;

  if( (vid_res =  place_vfuncs->video_open( ccfg, vidsec )) == NULL )
    return NULL;

  if( (filters = filter_setup( ccfg, &eres )) == NULL && eres == 1 )
  {
    place_vfuncs->video_close( vid_res );
    return NULL;
  }

  *place_filters = filters;
  return vid_res;
}

/*
 * close_taker:  Close a video device.
 *
 * Arguments:    vid_device = Video device to close
 *               vfuncs     = Vfuncs to access the video device.
 */

static
void close_taker( void *vid_device, Video_Funcs *vfuncs, Filter *filters ){
  vfuncs->video_close( vid_device );
  filter_destroy( filters );
}

void signal_handler( int signum ){
  if( signum == SIGTSTP ) return;
  if( signum == SIGCONT ) return;
#ifdef SIGINFO
  if( signum == SIGINFO ) return;
#endif
  camserv_log( MODNAME, "Received signal %d", signum );
  Abort = 1;
}

static
void setup_signals(){
  int i;

  for( i=0; i< NSIG; i++)
    if( i != SIGALRM &&
	i != SIGSEGV )
      signal( i, signal_handler );
}

/*
 * picture_single:  Take a single picture from the camera, and return
 *                  immediately.  This routine will do the open, init, snap
 *                  deinit, and close of the video device, and pass the picture
 *                  through all of the filters before returning.
 *
 * Arguments:       vfuncs         = Video funcs for the camera
 *                  ccfg           = Camera configuration
 *                  filters        = Filters as passed in by setup_filters.
 *
 * Return Values:   Returns -1 if the snapshot failed, 0 on success.

 */

int picture_single( CamConfig *ccfg, const char *fname, int presnaps )
{
  Filter *filters;
  Video_Funcs vfuncs;
  extern int errno;
  void *vid_device = NULL;
  char *pic_snap = NULL, vidsec[ 1024 ];
  Video_Geometry geom;
  Video_Info vinfo, out_vinfo;
  FILE *fp = NULL;
  float mfps;
  int errres, inited = 0;

  errres = 0;
  if( video_query_active_section( ccfg, vidsec, sizeof( vidsec ))==NULL)
    return -1;

  if( (fp = fopen( fname, "wb" )) == NULL ){
    camserv_log( MODNAME, "Output snapshot file \"%s\" error!",
	     fname );
    camserv_log( MODNAME, "--%s", strerror( errno ));
    errres = -1;
    goto snafu;
  }
    
  if( (vid_device = open_taker( ccfg, &vfuncs, &filters )) == NULL ){
    camserv_log( MODNAME, "Error opening video device!");
    errres = -1;
    goto snafu;
  }

  if( init_taker( &vfuncs, filters, vid_device, ccfg, NULL, &mfps, 0 ) == -1 ){
    errres = -1;
    goto snafu;
  }

  inited = 1;

  if( !(vfuncs.video_get_geom( vid_device, &geom ) | VIDEO_GEOM_MAX )){
    camserv_log( MODNAME, "Couldn't get max video extents!");
    errres = -1;
    goto snafu;
  }
  
  if( (pic_snap = malloc( geom.max_width * geom.max_height * 3 )) == NULL ){
    camserv_log( MODNAME, "Couldn't malloc %d bytes for picture!",
	     geom.max_width * geom.max_height * 3);
    errres = -1;
    goto snafu;
  }

  /* XXX -- Should all the snapshots be sent through the filters?  The filters
     could change based on how many snaps they've had .. HRMMMM...
     JMT - 10-31-99 */
  presnaps++;
  while( presnaps-- ){
    if( vfuncs.video_snap( vid_device, pic_snap, &vinfo, ccfg ) == -1 ){
      camserv_log( MODNAME, "Error snapping video image!");
      errres = -1;
      goto snafu;
    }
  }

  filter_list_process( filters, pic_snap, pic_snap, &vinfo, &out_vinfo );
  deinit_taker( &vfuncs, filters, vid_device, ccfg, NULL );
  close_taker( vid_device, &vfuncs, filters );
  inited = 0;
  vid_device = NULL;


  if( fwrite( pic_snap, out_vinfo.nbytes, 1, fp ) != 1){
    camserv_log( MODNAME, "Error writing output file!");
    camserv_log( MODNAME, "--%s", strerror( errno ));
    errres = -1;
    goto snafu;
  }

 snafu:
  if( pic_snap ) free( pic_snap );
  if( inited )   deinit_taker( &vfuncs, filters, vid_device, ccfg, NULL );
  if( vid_device ) close_taker( vid_device, &vfuncs, filters );
  if( fp != NULL)  fclose( fp );

  if( errres == -1 )
    unlink( fname );

  return errres;
}
               


int picture_taker( char *picture_memory, int amt_alloced,
		   CamConfig *camconfig, Socket *server_sock )
{
  Filter *filters;
  Video_Funcs vfuncs;
  SockSet *sset;
  void *vid_device;
  char *memhack_buf, vidsec[ 1024 ];
  int cpid, nFrames = 0;
  time_t start_time, cur_time, last_cur_time;
  float max_fps, cur_fps;

  if( (cpid = fork()) != 0 ) {
    return cpid;
  }

  if( video_query_active_section( camconfig, vidsec, 
				  sizeof( vidsec)) == NULL ){
    kill( getppid(), SIGINT );
    return -1;
  }

  if( (vid_device = open_taker( camconfig, &vfuncs, &filters )) == NULL ){
    camserv_log( MODNAME, "Error opening video device!");
    kill( getppid(), SIGINT );
    return -1;
  }

  if( init_taker( &vfuncs, filters, vid_device, camconfig,
		  &memhack_buf, &max_fps, 1 ) == -1 ){
    close_taker( vid_device, &vfuncs, filters );
    kill( getppid(), SIGINT );
    return -1;
  }

  if( (sset = sockset_new()) == NULL ){
    camserv_log( MODNAME, "Could not create new socket set!");
    close_taker( vid_device, &vfuncs, filters );
    kill( getppid(), SIGINT );
    return -1;
  }

  if( sockset_add_fd( sset, server_sock, server_sock ) == -1 ){
    camserv_log( MODNAME, "Could not add server socket to sockset!");
    sockset_dest( sset );
    kill( getppid(), SIGINT );
    return -1;
  }

  last_cur_time = 0;

  setup_signals();
  Abort = 0;
  while( !Abort ) {
    char buf[ 1024 ];
    int selres, dispatch_id;
    Video_Info vinfo, out_vinfo;

    sockset_reset( sset );
    selres = sockset_select( socket_query_fd( server_sock ) + 1,
			     sset, NULL, NULL );
    if( selres < 1 ) {
      camserv_log( MODNAME, "Bad return value from select()!");
      continue;
    }

    recv( socket_query_fd( server_sock ), buf, sizeof( buf ), 0 );
    if( sscanf( buf, "%d", &dispatch_id ) != 1 ){
      camserv_log( MODNAME, "Malformed message from server!" );
      continue;
    }

    if( dispatch_id == 0 ){  /* Snap a picture */
      char *pic_snap;
      int nsnaps;

      for( nsnaps=0; nsnaps < MAX_CONSEC_BAD_SNAPS; nsnaps++ ){
	if( memhack_buf ) pic_snap = memhack_buf;
	else              pic_snap = picture_memory;
	if( vfuncs.video_snap( vid_device, pic_snap, &vinfo,
				camconfig ) == -1 ){
	  camserv_log( MODNAME, "Error snapping video image .. reiniting!");
	  deinit_taker( &vfuncs, filters, vid_device, camconfig, 
			memhack_buf );
	  close_taker( vid_device, &vfuncs, filters );

	  /* Now reopen it and initailize it if we can */
	  /* This should always be set, since one cannot UNSET a variable */
	  video_query_active_section(camconfig,vidsec, sizeof( vidsec));

	  if( (vid_device = open_taker(camconfig, &vfuncs,&filters)) == NULL ||
	      init_taker( &vfuncs, filters, vid_device, camconfig, 
			  &memhack_buf, &max_fps, 1 ) == -1)
	  {
	    camserv_log( MODNAME, "Couldn't open camera!");
	    if( vid_device ) close_taker( vid_device, &vfuncs, filters );
	    goto error_exit;
	  }
	} else break;
      } 

      if( nsnaps == MAX_CONSEC_BAD_SNAPS ){
	camserv_log( MODNAME, "Too many bad snaps!  Aborting!");
	deinit_taker( &vfuncs, filters, vid_device, camconfig, memhack_buf );
	close_taker( vid_device, &vfuncs, filters );
	break;
      }

      filter_list_process( filters, pic_snap, picture_memory, 
			   &vinfo, &out_vinfo );
      report_picsnap( server_sock, out_vinfo.nbytes  );
      time( &cur_time );
      if( cur_time - last_cur_time > 10 ) /* Fudge factor */{
	time( &start_time );
	time( &cur_time );
	nFrames = 0;
      }
	
      if( max_fps != 0.0) {
	nFrames++;
	if( cur_time == start_time ) cur_time++;
	cur_fps = (double)nFrames / (double)(cur_time - start_time);
	last_cur_time = cur_time;
	
	if( cur_fps > max_fps ) 
	  sleep_abit( cur_fps, max_fps );
      }

    } else if( dispatch_id == 1 ) {
      init_taker( &vfuncs, filters, vid_device, camconfig,
		    &memhack_buf, &max_fps, 1 );
    } else if( dispatch_id == 2 ) {
      deinit_taker( &vfuncs, filters, vid_device, camconfig,
		    memhack_buf );
    } else if( dispatch_id == 9 ) {
      camserv_log( MODNAME, "Abort called!");
      Abort = 1;
    } else {
      camserv_log( MODNAME, "Invalid command %d received from server!", 
	       dispatch_id );
    }
  }

error_exit:

  camserv_log( MODNAME, "Exiting");
  deinit_taker( &vfuncs, filters, vid_device, camconfig, memhack_buf );
  close_taker( vid_device, &vfuncs, filters );
  exit( 1 );
  return 0;
}

