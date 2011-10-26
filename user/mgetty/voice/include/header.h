/*
 * voice_header.h
 *
 * Defines the header for raw modem data.
 *
 * $Id: header.h,v 1.4 1998/09/09 21:06:35 gert Exp $
 *
 */

typedef struct
     {
     char magic[4];
     char voice_modem_type[16];
     short compression;
     short speed;
     char bits;
     char reserved[7];
     } rmd_header;
