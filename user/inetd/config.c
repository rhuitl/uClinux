/* config.c: Config file reader.
 *
 * Copyright 1999 D. Jeff Dionne, <jeff@rt-control.com>
 *
 * This is free software, under the LGPL V2.0
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "cfgfile.h"

/* This is a quick and dirty config file parser.  It reads the file once for
 * each request, there is no cache.  Each line must be less than sizeof(cfgbuf) bytes.
 */

#define MAX_ARG 30
static char *args[MAX_ARG + 1];
static char cfgbuf[400];

static char *
ws(char **buf)
{
  char *b = *buf;
  char *p;
  char have_quote = 0;

  /* eat ws */
  while (*b &&
	 (*b == ' '  ||
	  *b == '\n' ||
	  *b == '\t')) b++;

  if (*b == '"') {
	have_quote = 1;
	b++;
  }

  p = b;

  /* find the end */
  while (*p &&
	 !((!have_quote && (*p == ' '  || *p == '\t')) || 
	  (have_quote && (*p == '"')) ||
	  (*p == '\n'))) {
	p++;
  }

  *p = 0;
  *buf = p+1;
  return b;
}

char **
cfgread(FILE *fp)
{
  char *ebuf;
  char *p;
  int i;

  if (!fp) {
    errno = EIO;
    return (void *)0;
  }
  
  while (fgets(cfgbuf, sizeof(cfgbuf), fp)) {

    /* ship comment lines */
    if (cfgbuf[0] == '#') continue;

    ebuf = cfgbuf + strlen(cfgbuf);

    p = cfgbuf;
    for (i = 0; i < MAX_ARG && p < ebuf; i++) {
      args[i] = ws(&p);
    }
    args[i] = (void *)0;

    /* return if we found something */
    if (strlen(args[0])) return args;
  }
  return (void *)0;
}

char **
cfgfind(FILE *fp, char *var)
{
  char **ret;
  char search[80];

  if (!fp || !var) {
    errno = EIO;
    return (void *)0;
  }

  strncpy(search, var, sizeof(search));

  fseek(fp, 0, SEEK_SET);
  while ((ret = cfgread(fp))) {
    if (!strcmp(ret[0], search)) return ret;
  }
  return (void *)0;
}
