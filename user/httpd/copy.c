/* copy.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>

static char copybuf[16384];

extern int TIMEOUT;

int
copy(FILE *read_f, FILE *write_f)
{
  int n;
  int i;
  int j;
  int oi;
  int wrote;

  alarm(TIMEOUT);
  while (n = fread(copybuf,1,sizeof(copybuf),read_f)) {
    alarm(TIMEOUT);
    wrote = fwrite(copybuf,n,1,write_f);
    alarm(TIMEOUT);
    if (wrote < 1)
    	return -1;
  }
  alarm(0);
  return 0;
}
