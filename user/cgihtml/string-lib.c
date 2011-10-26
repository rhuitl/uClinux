/* string-lib.c - generic string processing routines
   $Id: string-lib.c,v 1.5 1997/01/21 07:17:48 eekim Exp $

   Copyright (C) 1996 Eugene Eric Kim
   All Rights Reserved.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "string-lib.h"

char *newstr(char *str)
{
  char *tempstr = malloc(sizeof(char) * strlen(str) + 1);

  if (tempstr != NULL)
    strcpy(tempstr,str);
  return tempstr;
}

char *substr(char *str, int offset, int len)
{
  int slen, start, i;
  char *nstr;

  if (str == NULL)
    return NULL;
  else
    slen = strlen(str);
  nstr = malloc(sizeof(char) * slen + 1);
  if (offset >= 0)
    start = offset;
  else
    start = slen + offset - 1;
  if ( (start < 0) || (start > slen) ) /* invalid offset */
    return NULL;
  for (i = start; i < start+len; i++)
    nstr[i - start] = str[i];
  nstr[len] = '\0';
  return nstr;
}

char *replace_ltgt(char *str)
{
  int i,j = 0;
  char *new = malloc(sizeof(char) * (strlen(str) * 4 + 1));

  for (i = 0; i < strlen(str); i++) {
    if (str[i] == '<') {
      new[j] = '&';
      new[j+1] = 'l';
      new[j+2] = 't';
      new[j+3] = ';';
      j += 3;
    }
    else if (str[i] == '>') {
      new[j] = '&';
      new[j+1] = 'g';
      new[j+2] = 't';
      new[j+3] = ';';
      j += 3;
    }
    else
      new[j] = str[i];
    j++;
  }
  new[j] = '\0';
  return new;
}

char *lower_case(char *buffer)
{
  char *tempstr = buffer;

  while (*buffer != '\0') {
    if (isupper(*buffer))
      *buffer = tolower(*buffer);
    buffer++;
  }
  return tempstr;
}
