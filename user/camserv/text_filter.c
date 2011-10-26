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
#include <ctype.h>
#include <stdarg.h>

#include "camserv.h"
#include "camconfig.h"
#include "video.h"
#include "filter.h"
#include "fixfont.h"
#include "log.h"

#include "font_6x11.h"
#include "font_8x8.h"

#define MODNAME "textfilter"

#define COLOR_TRANSPARENT  0xff000000
#define COLOR_DEFAULT_BG   0x00000000  /* Colour defaults */
#define COLOR_DEFAULT_FG   0x00ffffff  /* Colour defaults */

typedef struct text_filter_st {
  FixedFont *font;
  int x, y;  /* Coordinates to place the text */
  int fg_color, bg_color;
  char txt[ 1024 ];
  int txt_mangle;  /* true if text is to be mangled via fmt_text, else false */
  /* valid if bg_color is a real colour */
  unsigned char bg_rval, bg_gval, bg_bval, bg_bwval;  
  /* valid if fg_color is a real colour */
  unsigned char fg_rval, fg_gval, fg_bval, fg_bwval;  
} TextFilter;


/*
 * valid_rgb_color:  Determine if a given string represents a valid
 *                   colour for the text filter.
 *    
 * Arguments:        color = A string to test 
 *
 * Return values:    Returns 0 if color is not of the form #RRGGBB, else 1
 */

static
int valid_rgb_color( const char *color ){
  int i;

  if( !color || strlen( color ) != 7 || color[ 0 ] != '#' )
    return 0;

  for( i=1; i< 7; i++ ){
    if(!isxdigit(color[i]))
        return 0;
  }
  return 1;
}

/*
 * process_color:  Process a color input, and return the integer value
 *                 of the colour components.
 *
 * Arguments:      color = String version of the color to process
 *                 is_bg = 1 if the color is the bg color, else 0
 *                 filt_num = Filter number of the current filter
 *                 rint = Location to store the red component of the color
 *                 gint = Location to store the green component of the color
 *                 bint = Location to store the blue component of the color
 *
 * Return values:  Always returns a valid colour value.  If the given colour
 *                 is an invalid one, the default will be used.  In the case
 *                 of transparency, the component values are not set, else
 *                 each color component value is set, and the colour is
 *                 returned.
 */

static
int process_color( const char *color, int is_bg, char *secname,
		   unsigned char *rint, unsigned char *gint, 
		   unsigned char *bint )
{
  if( !color || !strlen( color )){
    camserv_log( MODNAME, "Invalid [%s]:%s color given.  "
		 "Using default", secname, is_bg ? "bg" : "fg" );
    if( is_bg ) {
      *rint = (0x00ff0000 & COLOR_DEFAULT_BG) >> 16;
      *gint = (0x0000ff00 & COLOR_DEFAULT_BG) >> 8;
      *bint = (0x000000ff & COLOR_DEFAULT_BG) >> 0;
      return COLOR_DEFAULT_BG;
    } else {
      *rint = (0x00ff0000 & COLOR_DEFAULT_FG) >> 16;
      *gint = (0x0000ff00 & COLOR_DEFAULT_FG) >> 8;
      *bint = (0x000000ff & COLOR_DEFAULT_FG) >> 0;
      return COLOR_DEFAULT_FG;
    }
  }

  if( !strcmp( color, "transparent" ) )
    return COLOR_TRANSPARENT;
  else {
    int rf, gf, bf;

    if( !valid_rgb_color( color )){
      camserv_log( MODNAME, "Invalid [%s]:%s color given.  "
		   "Format should be: #RRGGBB, or 'transparent",
		   secname, is_bg ? "bg" : "fg" );
      if( is_bg ){
	*rint = (0x00ff0000 & COLOR_DEFAULT_BG) >> 16;
	*gint = (0x0000ff00 & COLOR_DEFAULT_BG) >> 8;
	*bint = (0x000000ff & COLOR_DEFAULT_BG) >> 0;
	return COLOR_DEFAULT_BG; 
      } else {
	*rint = (0x00ff0000 & COLOR_DEFAULT_FG) >> 16;
	*gint = (0x0000ff00 & COLOR_DEFAULT_FG) >> 8;
	*bint = (0x000000ff & COLOR_DEFAULT_FG) >> 0;
	return COLOR_DEFAULT_FG;
      }
    }
    sscanf( color, "%*c%2x%2x%2x", &rf, &gf, &bf );
    *rint = rf;
    *gint = gf;
    *bint = bf;
    return (*rint << 16) | (*gint << 8) | *bint;
  }
}

static
int valid_bw_color( const char *colour ) {
  int i;

  if( !colour || strlen( colour ) != 3 || colour[ 0 ] != '#' )
    return 0;

  for( i=1; i< 3; i++ ){
    if(!isxdigit(colour[i]))
        return 0;
  }
  return 1;
}

static
int process_bw( const char *strcolour, int is_bg, char *secname, 
		unsigned char *resval )
{
  if( !strcolour || !strlen( strcolour )){
    camserv_log( MODNAME, "Invalid [%s]:%s value given.  "
		 "Using default", secname, is_bg ? "bg" : "fg" );
    if( is_bg ) {
      *resval = (0x00ff0000 & COLOR_DEFAULT_BG) >> 16;
      return COLOR_DEFAULT_BG;
    } else {
      *resval = (0x00ff0000 & COLOR_DEFAULT_FG) >> 16;
      return COLOR_DEFAULT_FG;
    }
  }

  if( !strcmp( strcolour, "transparent" ) )
    return COLOR_TRANSPARENT;
  else {
    int bwval;
    
    if( !valid_bw_color( strcolour ) ){
      camserv_log( MODNAME, "Invalid [%s]:%s color given.  "
		   "Format should be: #CC, or 'transparent'",
		   secname, is_bg ? "bg" : "fg" );
      if( is_bg ) {
	*resval = (0x00ff0000 & COLOR_DEFAULT_BG) >> 16;
	return COLOR_DEFAULT_BG;
      } else {
	*resval = (0x00ff0000 & COLOR_DEFAULT_FG) >> 16;
	return COLOR_DEFAULT_FG;
      }
    }
    sscanf( strcolour, "%*c%2x", &bwval );
    *resval = bwval;
    return (*resval << 16);
  }
}

/*
 * filter_init:  Standard filter initialization routine.
 *
 * Filter variables:  textmod0_bg  = #RRGGBB or 'transparent' BG color of txt
 *                    textmod0_fg  = #RRGGBB or 'transparent' FG color of txt
 *                    textmod0_x   = X location of text
 *                    textmod0_y   = Y location of text
 *                   *textmod0_txt = Text to place
 *                    textmod0_mangle = 1 if txt must be mangled, else 0
 *                    textmod0_fontname = Fontname to use '6x11' or '8x8'
 *
 *                    Vars prefixed by '*' are required.  The '0' in all
 *                    of the variable names must be replaced with the
 *                    filter number currently assigned to the current text
 *                    filter.
 */                 

void *filter_init( CamConfig *ccfg, char *secname ){
  TextFilter *res;
  const char *fontname, *tmptxt;
  int err, is_bw;
  char buf[ 256 ];

  is_bw = camconfig_query_int( ccfg, SEC_VIDEO, VIDCONFIG_ISB_N_W, &err );
  if( err ) {
    camserv_log( MODNAME, "FATAL!  Configuration inconsistancy!");
    return NULL;
  }

  if( (res = malloc( sizeof( *res ))) == NULL ){
    camserv_log( MODNAME,"FATAL!  Could not allocate space for text filter!" );
    return NULL;
  }

  if( !is_bw ) {
    res->bg_color = process_color( camconfig_query_str( ccfg, secname, "bg" ),
				   1, secname,
				   &res->bg_rval,&res->bg_gval, &res->bg_bval);
    res->fg_color = process_color( camconfig_query_str( ccfg, secname, "fg" ),
				   1, secname,
				   &res->fg_rval,&res->fg_gval, &res->fg_bval);
  } else {
    res->bg_color = process_bw( camconfig_query_str( ccfg, secname, "bg" ), 
				0, secname,
				&res->bg_bwval );
    res->fg_color = process_bw( camconfig_query_str( ccfg, secname, "fg" ), 
				1, secname,
				&res->fg_bwval );
  }

  res->x = camconfig_query_def_int( ccfg, secname, "x", 0 );
  res->y = camconfig_query_def_int( ccfg, secname, "y", 0 );
  res->txt_mangle = camconfig_query_def_int( ccfg, secname, "mangle", 0 );
  tmptxt = camconfig_query_str( ccfg, secname, "text" );

  if( !tmptxt ) {
    camserv_log( MODNAME,
		 "FATAL!  %s configuration var invalid or unavailable", buf );
    free( res );
    return NULL;
  }
  strncpy( res->txt, tmptxt, sizeof( res->txt ));
  res->txt[ sizeof( res->txt ) - 1 ] = '\0';

  fontname = camconfig_query_str( ccfg, secname, "fontname" );
  
  if( fontname && !strcmp( fontname, "6x11" )) {
    res->font = fixed_font_create( font_6x11, 6, 11 );
  } else if( fontname && !strcmp( fontname, "8x8" )) {
    res->font = fixed_font_create( font_8x8, 8, 8 );
  } else {
    camserv_log( MODNAME, "Invalid [%s]:fontname, %s ... Using 6x11", secname,
		 fontname );
    res->font = fixed_font_create( font_6x11, 6, 11 );
  }

  if( res == NULL ){
    camserv_log( MODNAME, "FATAL!  Could not create font: %s", fontname );
    free( res );
    return NULL;
  }

  return res;
}

/*
 * filter_deinit:  Standard filter deinitialization routine
 */

void filter_deinit( void *filter_dat ){
  TextFilter *tfilt = filter_dat;

  fixed_font_destroy( tfilt->font );
  free( tfilt );
}

static
int txt_is_offscreen( const TextFilter *tfilt, const Video_Info *vinfo_in,
		      int txtlen )
{
  /* We must be able to place at least 1 char */
  if( tfilt->x >= (vinfo_in->width - tfilt->font->width)) 
    return 1; /* Too far right */
  else if( tfilt->x < 0 && 
	   (tfilt->x + tfilt->font->width * txtlen < tfilt->font->width))
    return 1; /* Too far left! */

  if( tfilt->y >= vinfo_in->height  ) 
    return 1; /* Below the picture */
  else if( tfilt->y < 0 && -tfilt->y >= tfilt->font->height ) 
    return 1; /* Too far above the picture */
  
  return 0;
}

void filter_func( char *in_data, char **out_data, void *cldat, 
		  const Video_Info *vinfo_in, Video_Info *vinfo_out )
{
  TextFilter *tfilt = cldat;
  unsigned char *outp, *packp, *init_outp;
  char *txtp, use_txt[ 1024 ];
  int i, y, last_y, start_y, first_char, last_char, use_txt_len;
  int Bpp; /* Bytes for each pixel -- 1 == B&W, 3 == RGB */

  *vinfo_out = *vinfo_in;
  *out_data = in_data;
  
  if( tfilt->txt_mangle ) {
      struct tm ltime;
      time_t now;
      
      time(&now);
      ltime = *localtime(&now); 
      strftime( use_txt, sizeof(use_txt), tfilt->txt, &ltime);
  } else
    strncpy( use_txt, tfilt->txt, sizeof( use_txt ) );

  use_txt[ sizeof( use_txt ) - 1 ] = '\0';
  use_txt_len = strlen( use_txt );

  /* First, stupidity checking to see if we are even going to be able
     to put anything on the picture */
  if( txt_is_offscreen( tfilt, vinfo_in, use_txt_len ) )
    return;

  if( tfilt->y < 0 && -tfilt->y < tfilt->font->height ) {
    start_y = -tfilt->y;  /* Straddling the picture */
  } else
    start_y = 0;

  /* Figure out the ending, in case we might run off the bottom */
  if( tfilt->y + tfilt->font->height > vinfo_in->height ) 
    last_y = tfilt->font->height - 
      (tfilt->y + tfilt->font->height - vinfo_in->height);
  else
    last_y = tfilt->font->height;

  /* This isn't the best situation, but it is more optimal than doing
     the compare for each pixel.  On a per-char basis, figure out where
     we can place the first full char on the screen.  I.e. if char[0] is off
     to the left somewhere, we don't need to place it. */
  
  if( tfilt->x < 0 )
    first_char = (-tfilt->x / tfilt->font->width) + 1;
  else
    first_char = 0;
  
  if( tfilt->x + tfilt->font->width * use_txt_len > vinfo_in->width )
    last_char = (vinfo_in->width - tfilt->x) / tfilt->font->width - 1;
  else
    last_char = use_txt_len - 1;

  if( vinfo_in->is_black_white ) Bpp = 1;
  else Bpp = 3;

  /* outp will contain the index into the picture, for the pixel
     manglifiation */
  if( tfilt->y < 0 )
    init_outp = in_data + Bpp * (0 * vinfo_in->width + tfilt->x);
  else
    init_outp = in_data + Bpp * (tfilt->y * vinfo_in->width + tfilt->x);

  outp = init_outp;

  for( y=start_y;
       y< last_y;
       y++, outp = init_outp + (y - start_y) * Bpp * vinfo_in->width )
  {

    outp += first_char * Bpp * tfilt->font->width;

    /* For each letter, print it's rasterized line */
    for( txtp=&use_txt[0] + first_char; 
	 txtp <= &use_txt[0] + last_char; txtp++ ){
      packp = tfilt->font->chars[ (int) *txtp ].line_data[ y ];
      while( *packp != FFONT_RUN_TERM_CHAR ) {
	if( *packp < 16 ) {
	  if( tfilt->fg_color != COLOR_TRANSPARENT ) {
	    if( Bpp == 3 ) {
	      for( i=0; i <= *packp; i++ ){  /* Turn the pixel on */
		*outp++ = tfilt->fg_rval;
		*outp++ = tfilt->fg_gval;
		*outp++ = tfilt->fg_bval;
	      } 
	    } else {
	      for( i=0; i <= *packp; i++ ){
		*outp++ = tfilt->fg_bwval;
	      }
	    }
	  } else {
	    outp += Bpp * (*packp + 1);
	  }
	} else if( *packp < 32 ) {
	  if( tfilt->bg_color != COLOR_TRANSPARENT ) {
	    if( Bpp == 3 ) {
	      for( i=16; i<= *packp; i++ ){  /* Turn the pixel off */
		*outp++ = tfilt->bg_rval;
		*outp++ = tfilt->bg_gval;
		*outp++ = tfilt->bg_bval;
	      }
	    } else {
	      for( i=16; i<= *packp; i++ ){
		*outp++ = tfilt->bg_bwval;
	      }
	    }
	  } else {
	    outp += Bpp * (*packp - 15);
	  }
	} else {
	  camserv_log( MODNAME, "BOGUS PACKED FONT!");
	}
	packp++;
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

  if( (res = modinfo_create( 7 )) == NULL )
    return NULL;

  modinfo_varname_set( res, 0, "bg" );
  modinfo_desc_set( res, 0, "Text Background Color (#CC if B&W, #RRGGBB, or "
		    "'transparent')");
  res->vars[ 0 ].type = MODINFO_TYPE_STR;
  
  modinfo_varname_set( res, 1, "fg" );
  modinfo_desc_set( res, 1, "Text Foreground Color (#CC if B&W, #RRGGBB, or "
		    "'transparent')");
  res->vars[ 1 ].type = MODINFO_TYPE_STR;

  modinfo_varname_set( res, 2, "x" );
  modinfo_desc_set( res, 2, "X pixel location of the text (from the left)" );
  res->vars[ 2 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 3, "y" );
  modinfo_desc_set( res, 3, "Y pixel location of the text (from the top)" );
  res->vars[ 3 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 4, "mangle" );
  modinfo_desc_set( res, 4, "Enable text mangling (1==on, 0==off)" );
  res->vars[ 4 ].type = MODINFO_TYPE_INT;

  modinfo_varname_set( res, 5, "text" );
  modinfo_desc_set( res, 5, "Text to display" );
  res->vars[ 5 ].type = MODINFO_TYPE_STR;

  modinfo_varname_set( res, 6, "fontname" );
  modinfo_desc_set( res, 6, "Font to display text in ('6x11' or '8x8')" );
  res->vars[ 6 ].type = MODINFO_TYPE_STR;
  

  return res;
}
