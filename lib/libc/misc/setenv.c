/* Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
 * This file is part of the Linux-8086 C library and is distributed
 * under the GNU Library General Public License.
 */
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

extern char ** environ;
#define ADD_NUM 4

int
setenv(var, value, overwrite)
const char * var;
const char * value;
int overwrite;
{
static char ** mall_env = 0;
static int extras = 0;
   char **p, **d;
   char * t;
   int len;

   len = strlen(var);

   if (!environ) {
   	environ = (char**)malloc(ADD_NUM * sizeof(char*));
   	memset(environ, 0, sizeof(char*)*ADD_NUM);
   	extras = ADD_NUM;
   }

   for(p=environ; *p; p++)
   {
      if( memcmp(var, *p, len) == 0 && (*p)[len] == '=' )
      {
         if (!overwrite)
         	return -1;
         while( p[0] = p[1] ) p++;
         extras++;
         break;
      }
   }

   if( extras <= 0 )	/* Need more space */
   {
      d = malloc((p-environ+1+ADD_NUM)*sizeof(char*));
      if( d == 0 ) return -1;

      memcpy((void*) d, (void*) environ, (p-environ+1)*sizeof(char*));
      p = d + (p-environ);
      extras=ADD_NUM;

      if( mall_env ) free(mall_env);
      environ = d;
      mall_env = d;
   }

   t = malloc(len + 1 + strlen(value) + 1);
   if (!t)
   	return -1;

   strcpy(t, var);
   strcat(t, "=");
   strcat(t, value);

   *p++ = (char*)t;
   *p = '\0';
   extras--;

   return 0;
}


