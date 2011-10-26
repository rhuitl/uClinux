/*
 * Copyright (C) 1991,1992 Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * This file is part of NASE A60.
 * 
 * NASE A60 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * NASE A60 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with NASE A60; see the file COPYING.  If not, write to the Free
 * Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * bltin.h:					sept '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef BLYIN_H_HOOK
#define BLYIN_H_HOOK

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


extern void init_bltin P((void));


#undef P

#endif /* BLYIN_H_HOOK */
