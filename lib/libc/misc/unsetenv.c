/* Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
 * This file is part of the Linux-8086 C library and is distributed
 * under the GNU Library General Public License.
 */
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

extern char ** environ;

void unsetenv(var)
const char * var;
{
   char **p;
   int len;

   len = strlen(var);
   
   if (!environ)
      return;

   for(p=environ; *p; p++)
   {
      if( memcmp(var, *p, len) == 0 && (*p)[len] == '=' )
	 break;
   }
   for (; *p; p++)
	 p[0] = p[1];
}


