/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _COMPAT_H
#define _COMPAT_H

#include "config.h"

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

#ifdef SUNOS
#define NOBLOCK O_NDELAY
#else
#define NOBLOCK O_NONBLOCK
#endif

#ifndef MAP_FILE
#define MAP_OPTIONS MAP_PRIVATE	/* Sun */
#else
#define MAP_OPTIONS MAP_FILE|MAP_PRIVATE	/* Linux */
#endif

#ifdef AIX
#include <sys/select.h>
#endif

#endif
