/* html-lib.c - C routines that output various HTML constructs
   Eugene Kim, <eekim@eekim.com>
   $Id: html-lib.c,v 1.8 1997/02/03 06:40:23 eekim Exp $

   Copyright (C) 1996, 1997 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "html-lib.h"

/* HTTP headers */

void html_header()
{
  printf("Content-type: text/html\n\n");
}

void mime_header(char *mime)
/* char *mime = valid mime type */
{
  printf("Content-type: %s\n\n",mime);
}

void nph_header(char *status)
{
  printf("HTTP/1.0 %s\n",status);
  printf("Server: CGI using cgihtml\n");
}

void show_html_page(char *loc)
{
  printf("Location: %s\n\n",loc);
}

void status(char *status)
{
  printf("Status: %s\n",status);
}

void pragma(char *msg)
{
  printf("Pragma: %s\n",msg);
}

void set_cookie(char *name, char *value, char *expires, char *path,
		char *domain, short secure)
{
  /* in later version, do checks for valid variables */
  printf("Set-Cookie: %s=%s;",name,value);
  if (expires != NULL)
    printf(" EXPIRES=%s;",expires);
  if (path != NULL)
    printf(" PATH=%s;",path);
  if (domain != NULL)
    printf(" DOMAIN=%s;",domain);
  if (secure)
    printf(" SECURE");
  printf("\n");
}

/* HTML shortcuts */

void html_begin(char *title)
{
  printf("<html> <head>\n");
  printf("<title>%s</title>\n",title);
  printf("</head>\n\n");
  printf("<body>\n");
}

void html_end()
{
  printf("</body> </html>\n");
}

/* what's the best way to implement these tags?  Think about this a little
more before you settle on a way to do this. */

void h1(char *header)
{
  printf("<h1>%s</h1>\n",header);
}

void h2(char *header)
{
  printf("<h2>%s</h2>\n",header);
}

void h3(char *header)
{
  printf("<h3>%s</h3>\n",header);
}

void h4(char *header)
{
  printf("<h4>%s</h4>\n",header);
}

void h5(char *header)
{
  printf("<h5>%s</h5>\n",header);
}

void h6(char *header)
{
  printf("<h6>%s</h6>\n",header);
}

/* state related functions */
void hidden(char *name, char *value)
{
  printf("<input type=hidden name=\"%s\" value=\"%s\">\n",name,value);
}
