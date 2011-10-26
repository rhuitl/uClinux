/* 
 *  gloadavg.c - get load average for Linux
 *  Copyright (C) 1993  Thomas Koenig
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _POSIX_SOURCE 1

/* System Headers */

#include <stdio.h>

/* Local headers */

#include "getloadavg.h"

/* File scope variables */

static char rcsid[] = "$Id: getloadavg.c,v 1.4 1997/03/12 19:36:06 ig25 Exp $";

#define PROC_DIR "/proc"

/* Global functions */

int
getloadavg(double *result, int n)
/* return the current load average as a floating point number, or <0 for
 * error
 */
{
    FILE *fp;
    int i;

    if (n > 3)
	n = 3;

    if ((fp = fopen(PROC_DIR "/loadavg", "r")) == NULL)
	i = -1;
    else {
	for (i = 0; i < n; i++) {
	    if (fscanf(fp, "%lf", result) != 1)
		goto end;
	    result++;
	}
    }
  end:
    fclose(fp);
    return i;
}
