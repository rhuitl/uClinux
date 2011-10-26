/* test.cgi.c - Uses functions print_cgi_env() and print_entries()
     to test CGI.

   Eugene Kim, eekim@fas.harvard.edu
   $Id: test.cgi.c,v 1.5 1997/01/21 07:21:11 eekim Exp $

   Copyright (C) 1996 Eugene Eric Kim
   All Rights Reserved
*/

#include <stdio.h>
#include "html-lib.h"
#include "cgi-lib.h"

int main()
{
  llist entries;
  int status;

  html_header();
  html_begin("Test CGI");
  h1("CGI Test Program");
  printf("<hr>\n");
  h2("CGI Environment Variables");
  print_cgi_env();
  status = read_cgi_input(&entries);
  printf("<h2>Status = %d</h2>\n",status);
  h2("CGI Entries");
  print_entries(entries);
  html_end();
  list_clear(&entries);
  return 0;
}

