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
 * type.h:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef TYPE_H_HOOK
#define TYPE_H_HOOK

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


enum type_tag {
	ty_unknown,
	ty_proc,
	ty_switch,
	ty_label,
	ty_string,
	ty_integer,
	ty_int_array,
	ty_int_proc,
	ty_real,
	ty_real_array,
	ty_real_proc,
	ty_bool,
	ty_bool_array,
	ty_bool_proc,
	TY_LAST_TYPE_TAG
};

#define TIS_ARR(x)	((x) == ty_int_array || (x) == ty_real_array \
			 || (x) == ty_bool_array)
#define TIS_FUNC(x)	((x) == ty_int_proc || (x) == ty_real_proc \
			 || (x) == ty_bool_proc)
#define TIS_PROC(x)	((x) == ty_int_proc || (x) == ty_real_proc \
			 || (x) == ty_bool_proc || (x) == ty_proc)
#define TIS_NUM(x)	((x) == ty_real || (x) == ty_integer)
#define TIS_BOOL(x)	((x) == ty_bool)
#define TIS_BASET(x)	(TIS_NUM(x) || TIS_BOOL(x))
#define TIS_SPECT(x)	(TIS_PROC(x) || (x) == ty_switch || (x) == ty_label \
			 || (x) == ty_string)
#define TAR_TYPE(x)	((x) + 1)
#define TAR_BASE(x)	((x) - 1)
#define TPROC_TYPE(x)	((x) + 2)
#define TPROC_BASE(x)	((x) - 2)
#define BASE_TYPE(x)	(TIS_ARR(x) ? TAR_BASE(x) : \
			 (TIS_FUNC(x) ? TPROC_BASE(x) : (x)))
#define TIS_SVALT(x)	(TIS_NUM(x) || TIS_BOOL(x) || TIS_FUNC(x))

extern char *type_tag_name[];


#undef P

#endif /* TYPE_H_HOOK */
