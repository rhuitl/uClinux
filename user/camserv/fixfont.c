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

#include "fixfont.h"

/*
 * fixed_font_char_pack:  Pack a char into a FixedFontChar structure
 *                        from the header-file-thingy.  
 *
 * Arguments:             fontoffset = Pointer to character (offset in char[])
 *                        width      = Width of character
 *                        height     = Height of character
 *                        buffer     = Location to place packed character
 */

void fixed_font_char_pack( const unsigned char *fontoffset, 
			   int width, int height,
			   FixedFontChar *buffer )
{
  unsigned char *line_data_cp;
  const unsigned char *fontcp;
  int x, y, runtype;

  /* Create packed representation of font information. 
     Since the fonts in this format are at most 16 pixels wide, we have
     a lot of power to make this 'line_data' be anything we want.  The format
     of line_data is as follows:

     Each line represents information 'runs'.  Each run is given by 1
     char in the line_data.  If 0 <= char < 16, then the next
     char + 1 pixels are turned 'on'.  If 16 <= char < 32, then the
     next char - 15 pixels are turned 'off'.  If char == 255, then
     the runs for the line are completed, and scanning should cease. */

  for( y=0, fontcp = fontoffset; y< height; y++, fontcp++ ){
    line_data_cp = buffer->line_data[ y ];
    runtype = FFONT_RUN_NONE;
    for( x=7; x >= 0; x --){
      if( *fontcp & (1 << x )) { /* Pixel on */
	if( runtype == FFONT_RUN_NONE ) {
	  runtype = FFONT_RUN_ON;
	  *line_data_cp = 0;
	} else if( runtype == FFONT_RUN_ON ) { /* Continuation */
	  (*line_data_cp)++;
	} else {
	  /* Went from off to on */
	  line_data_cp++;
	  runtype = FFONT_RUN_ON;
	  *line_data_cp = 0;
	}
      } else {
	if( runtype == FFONT_RUN_NONE ) {
	  runtype = FFONT_RUN_OFF;
	  *line_data_cp = 16;
	} else if( runtype == FFONT_RUN_OFF ) {
	  (*line_data_cp)++;
	} else {
	  line_data_cp++;
	  runtype = FFONT_RUN_OFF;
	  *line_data_cp = 16;
	}
      }
    }

    /* Finish off the run with the terminator */
    line_data_cp++;
    *line_data_cp = FFONT_RUN_TERM_CHAR;
  }
}

/*
 * fixed_font_destroy:  Destroy a fixed font structure
 *
 * Arguments:           ffont = font to destroy.
 */

void fixed_font_destroy( FixedFont *ffont ){
  free( ffont );
}

/*
 * fixed_font_create:  Create a packed fixed font structure given
 *                     an array containing the font info.
 *
 * Arguments:          fontset = Fixed font info from the header.
 *                     width   = Width of each char in fontset
 *                     height  = Height of each char in fontset
 *
 * Return values:      Returns NULL on failure, else a pointer to a new
 *                     FixedFont struct on success.
 */

FixedFont *fixed_font_create( const unsigned char fontset[], 
			      int width, int height )
{
  FixedFont *res;
  int i;

  if( width < 0 || width > FFONT_MAX_WIDTH ) return NULL;
  if( height < 0 || height > FFONT_MAX_HEIGHT) return NULL;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  res->width = width;
  res->height = height;

  for( i=0; i< 256; i++ ){
    fixed_font_char_pack( &fontset[ i * height ], width, height, 
			  &res->chars[ i ]);
  }
  return res;
}

/*
 * fixed_font_print_char:  Print a character from the fixed font on stdout.
 *                         Primarily used for debugging.
 *
 * Arguments:              ffont = Fixed font to use
 *                         charval = Character value between 0 and 255 inclusiv
 */
 
void fixed_font_print_char( const FixedFont *ffont, int charval ){
  int y, i;
  const unsigned char *cp;

  for( y=0; y< ffont->height; y++ ){
    cp = ffont->chars[ charval ].line_data[ y ];
    while( *cp != FFONT_RUN_TERM_CHAR ) {
      if( *cp < 16 ) {
	for( i=0; i<= *cp; i++ )
	  printf(" " );
      } else if( *cp < 32 ) {
	for( i=16; i<= *cp; i++ )
	  printf( "O" );
      } else {
	printf("!\n");
      }
      cp++;
    }
    printf("\n");
  }
}

