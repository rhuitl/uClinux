#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "camserv.h"
#include "camconfig.h"
#include "video.h"
#include "filter.h"
#include "log.h"

#define MODNAME "randfilter"

typedef struct rand_filter_st {
  int colored_pixels;
  int num_perline;
} RandFilter;


/*
 * filter_init:  Standard filter initialization routine.
 *
 * Filter variables:  randmod_perline = max # of random pixels per line
 *                    randmod_colordpix = Use colored pixels
 */

void *filter_init( CamConfig *ccfg, char *section_name ){
  RandFilter *res;

  if( (res = malloc( sizeof( *res ))) == NULL ){
    camserv_log( MODNAME, 
		 "FATAL!  Could not allocate space for random filter!" );
    return NULL;
  }

  res->num_perline = camconfig_query_def_int( ccfg, section_name,
					      "num_perline", 20 );
  res->colored_pixels = camconfig_query_def_int( ccfg, section_name,
						 "coloredpix",1);
  return res;
}

/*
 * filter_deinit:  Standard filter deinit routine 
 */

void filter_deinit( void *filter_dat ){
  RandFilter *rfilt = filter_dat;

  free( rfilt );
}

void filter_func( char *in_data, char **out_data, void *cldat, 
		  const Video_Info *vinfo_in, Video_Info *vinfo_out )
{
  RandFilter *rfilt = cldat;
  int rowspan, i, j, randval;
  unsigned char *cp, *outp;

  *vinfo_out = *vinfo_in;
  *out_data = in_data;

  if( vinfo_in->is_black_white ) { /* UNTESTED */
    rowspan = vinfo_in->width;
    
    for( i=0, cp = in_data; i< vinfo_in->height; i++, cp += rowspan ) {
      randval = random() % 100;
      for( j=0; j< randval; j++ ){
	outp = cp + (random() % vinfo_in->width );
	*outp = random() % 256;
      }
    }
  } else {
    /* Pick random spots per line */
    rowspan = vinfo_in->width * 3;

    for( i=0, cp = in_data; i< vinfo_in->height; i++, cp += rowspan ){
      randval = random() % rfilt->num_perline;
      if( rfilt->colored_pixels ) {
	for( j=0; j< randval; j++ ){
	  outp = cp + 3*(random() % vinfo_in->width );
	  *(outp + 0) = random() % 255;
	  *(outp + 1) = random() % 255;
	  *(outp + 2) = random() % 255;
	}
      } else {
	for( j=0; j< randval; j++ ){
	  outp = cp + 3*(random() % vinfo_in->width );
	  *(outp + 0) = 255 - *(outp + 0 );
	  *(outp + 1) = 255 - *(outp + 1 );
	  *(outp + 2) = 255 - *(outp + 2 );
	}
      }
    }
  }
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

  if( (res = modinfo_create( 2 )) == NULL )
    return NULL;

  modinfo_varname_set( res, 0, "num_perline" );
  modinfo_desc_set( res, 0, "Maximum number of speckles per line" );
  res->vars[ 0 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 1, "coloredpix" );
  modinfo_desc_set( res, 1, "Enable colored pixels (1==on, 0==off)");
  res->vars[ 1 ].type = MODINFO_TYPE_INT;

  return res;
}
