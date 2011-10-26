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
 * conv.h:					oct '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * conversion of numerical values.
 * 'real' to 'integer'  and  'integer' to 'real'.
 */

#ifndef CONV_H_HOOK
#define CONV_H_HOOK


#ifdef __GNUC__
# include <limits.h>
#else /* ! __GNUC__ */
# ifndef NO_LIMITS_H
#  include <limits.h>
# endif /* NO_LIMITS_H */
#endif /* ! __GNUC__ */


/*
 * use these values, if not avail ...
 */

#ifndef LONG_MAX
#define LONG_MAX         2147483647L
#endif
#ifndef LONG_MIN
/*
 * problem using -2147483648: if '-' is scanned as unary minus, the
 * positive number is greater than LONG_MAX ... 
 */
#define LONG_MIN        (-LONG_MAX-1)
#endif



/*
 * conversion of integer value to real value (and vice versa).
 */

#define IVAL2RVAL(l)	((double) (l))

#define RVAL2IVAL(x)	(((x) + 0.5 >= (double) LONG_MAX) \
			 ? LONG_MAX \
			 : ((x) - 0.5 <= (double) LONG_MIN) \
			 ? LONG_MIN \
			 : ((x) > 0) ? (long) ((x) + 0.5) \
			 	     : (long) ((x) - 0.5))

#define RVALTRUNC(x)	(((x) > (double) LONG_MAX) \
			 ? LONG_MAX \
			 : ((x) < (double) LONG_MIN) \
			 ? LONG_MIN \
			 : (long) (x))

#undef P

#endif /* CONV_H_HOOK */
