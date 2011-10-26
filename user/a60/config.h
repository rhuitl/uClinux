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
 * config.h:					may '91
 *
 * configurational parameters:
 */

#ifndef CONFIG_H_HOOK
#define CONFIG_H_HOOK

/*
 * which C compiler for mkc-compilation:
 * (un*x choice)
 */

#ifndef CC_TO_USE
# define CC_TO_USE	"gcc"		/* love that engine */
# define MKC_GNUC_TARGET		/* Warp 9, Mr. Chekov */
#endif

#ifndef CC_OPTS
# ifdef MKC_GNUC_TARGET
#  define CC_OPTS		"-w"	/* ignore quentionable conversions */
# else
#  define CC_OPTS		""	/* none */
# endif
#endif

#endif /* CONFIG_H_HOOK */
