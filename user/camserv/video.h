#ifndef VIDEO_DOT_H
#define VIDEO_DOT_H

#include "modinfo.h"
#include "camconfig.h"

#define VIDCONFIG_PREFIX     ""
#define VIDCONFIG_PATH       ( VIDCONFIG_PREFIX "path" )
#define VIDCONFIG_WIDTH      ( VIDCONFIG_PREFIX "width" )
#define VIDCONFIG_HEIGHT     ( VIDCONFIG_PREFIX "height" )
#define VIDCONFIG_MAXWIDTH   ( VIDCONFIG_PREFIX "maxwidth" )
#define VIDCONFIG_MAXHEIGHT  ( VIDCONFIG_PREFIX "maxheight" )
#define VIDCONFIG_MINWIDTH   ( VIDCONFIG_PREFIX "minwidth" )
#define VIDCONFIG_MINHEIGHT  ( VIDCONFIG_PREFIX "minheight" )
#define VIDCONFIG_ISB_N_W    ( VIDCONFIG_PREFIX "isblackwhite" )

#define VIDSYM_OPEN     "video_open"
#define VIDSYM_CLOSE    "video_close"
#define VIDSYM_INIT     "video_init"
#define VIDSYM_DEINIT   "video_deinit"
#define VIDSYM_SNAP     "video_snap" 
#define VIDSYM_GET_GEOM "video_get_geom" 
#define VIDSYM_MODINFO  "modinfo_query"

#define VIDEO_GEOM_MAX  1 << 0
#define VIDEO_GEOM_MIN  1 << 1
#define VIDEO_GEOM_CUR  1 << 2

typedef struct {
  int max_width, max_height;
  int min_width, min_height;
  int cur_width, cur_height;
} Video_Geometry;

typedef struct {
  int width, height;
  int is_black_white;
  int nbytes;
} Video_Info;

typedef struct {
  void *(*video_open)( CamConfig *ccfg, char *section_name );
  void (*video_close)( void *device_info );
  int (*video_init)( void *device_info, CamConfig *ccfg );
  int (*video_deinit)( void *device_info );
  int (*video_snap)( void *device_info, char *buffer, Video_Info *vinfo,
		     CamConfig *ccfg );
  int (*video_get_geom)( void *device_info, Video_Geometry *vidgeom );
  ModInfo_QueryFunc video_modinfo_query;
} Video_Funcs;

extern int video_setup_funcs( CamConfig *ccfg, Video_Funcs *vfuncs );
extern char *video_query_active_section( CamConfig *ccfg, char *place, 
					 int size);
#endif
