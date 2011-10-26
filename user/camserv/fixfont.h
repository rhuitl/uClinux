#ifndef FIXFONT_DOT_H
#define FIXFONT_DOT_H

#define FFONT_MAX_WIDTH   8
#define FFONT_MAX_HEIGHT  11

#define FFONT_RUN_NONE      0
#define FFONT_RUN_ON        1
#define FFONT_RUN_OFF       2
#define FFONT_RUN_TERM_CHAR 255

typedef struct font_char_st {
  unsigned char line_data[ FFONT_MAX_HEIGHT ][ FFONT_MAX_WIDTH * 2 + 1];
} FixedFontChar;

typedef struct fixed_font_st {
  int width, height;
  FixedFontChar chars[ 256 ];
} FixedFont;


extern void fixed_font_print_char( const FixedFont *ffont, int charval );
extern void fixed_font_destroy( FixedFont *ffont );
extern FixedFont *fixed_font_create( const unsigned char fontset[], 
				     int width, int height );
extern void fixed_font_char_pack( const unsigned char *fontoffset, 
				  int width, int height,
				  FixedFontChar *buffer );
#endif
