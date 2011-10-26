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
 * block.h:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef BLOCK_H_HOOK
#define BLOCK_H_HOOK

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


/*
 * a block is something between 'begin' and 'end'; symtab represents
 * the declarations in this block and tree stmt the body.
 * (ext_ref is for use in mkc)
 */

typedef struct _block {
	struct _symtab *symtab;
	struct _tree *stmt;
	struct _block *up;
	int nact;			/* number of act-cells */
	int ext_ref;			/* external references in this block */
} BLOCK;


extern struct _data *new_data P((void));


#undef P

#endif /* BLOCK_H_HOOK */
