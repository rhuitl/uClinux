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
 * run.h:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef RUN_H_HOOK
#define RUN_H_HOOK

#include <setjmp.h>
#include "eval.h"

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


enum run_tag {
	r_block,
	r_stmt,
	r_expr,
	r_assign,
	r_loop,
	r_unop,
	r_binop,
	r_last_run_tag
};


typedef struct _value {
	int valid;
	union {
		long ival;		/* integer/bool value */
		double rval;		/* real value */
		char *string;		/* string value */
	} u;
} VALUE;


/*
 * data elems.
 */

typedef struct _data {
	union {
		struct _value *val;	/* simple or array value */
		struct _pexpr pexpr;	/* call by name parm */
	} u;
} DATA;


/*
 * additional information for array activaton.
 */

typedef struct _act_bound {
	long from, til, mpl;		/* runtime values */
	struct _act_bound *next;
} ACT_BOUND;

typedef struct _arract {
	struct _act_bound *act_bound;
	long size;
} ARRACT;

typedef struct _swact {
	struct _symtab **targs;
	long nelm;
} SWACT;


/*
 * activation cell.
 */

typedef struct _activ {
	struct _symtab *sym;
	struct _swact *swact;		/* switch list */
	struct _data *data;	
	struct _arract *arract;		/* additional for array's */
} ACTIV;


/*
 * list of the static chained scopes.
 */

typedef struct _cblock {
	struct _block *block;		/* the block itself */
	int nact;			/* number of activations */
	struct _activ *activ;		/* the activation */
	int activated;			/* flag for activation. */
	jmp_buf jmpbuf;			/* marking this frame */
	struct _cblock *next;		/* the ``up'' block */
} CBLOCK;


/*
 * list of context's 
 */

typedef struct _cbelm {
	struct _cblock *cblock;
	struct _cbelm *next;
} CBELM;

extern CBLOCK *act_cblock;			/* active scope */

extern void init_lex P((void));
extern void interpret P((void));

extern void run_dummy P((struct _tree *));
extern void run_assign P((struct _tree *));
extern void run_block P((struct _tree *));
extern void run_goto P((struct _tree *));
extern void run_ifstmt P((struct _tree *));
extern void run_forstmt P((struct _tree *));
extern void run_proc P((struct _tree *));

extern void push_cblock P((struct _cblock *));
extern void pop_cblock P((void));

extern void push_valaddr P((char *, int, struct _symtab *, long));
extern void exec_fcall P((char *, int, struct _symtab *, struct _funcall *));
extern void push_spec P((char *, int, struct _symtab *));
extern void push_spec_pexpr P((struct _pexpr *));
extern void assign_vals P((int));
extern struct _data *get_sym_data P((struct _symtab *));
extern struct _swact *get_swact P((struct _symtab *));

#undef P

#endif /* RUN_H_HOOK */
