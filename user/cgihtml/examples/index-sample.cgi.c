/* index-sample.cgi.c - sample index.cgi program
   Will determine whether the browser accepts images or not and sends
   the appropriate page.

   Eugene Kim, eekim@fas.harvard.edu
   $Id: index-sample.cgi.c,v 1.1 1995/08/13 21:30:53 eekim Exp $

   Copyright (C) 1995 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdio.h>
#include "cgi-lib.h"
#include "html-lib.h"

#define TEXT_PAGE "/index-txt.html"   /* text HTML home page */
#define IMAGE_PAGE "/index-img.html"  /* graphical HTML home page */

int main() {
  if (accept_image())
    show_html_page(TEXT_PAGE);
  else
    show_html_page(IMAGE_PAGE);
  exit(0);
}
