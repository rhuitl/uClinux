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
 * eval.h:					sept '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef EVAL_H_HOOK
#define EVAL_H_HOOK

#include "expr.h"

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


enum eval_tag {
	ev_none,
	ev_ival,
	ev_rval,
	ev_bool,
	ev_unop,
	ev_binop,
	ev_valaddr,
	ev_label,
	ev_switch,
	ev_proc,
	ev_string,
	ev_expr,
	ev_sym,
	r_last_eval_tag
};

#define EV_PLAIN(x)	((x) == ev_ival || (x) == ev_rval || (x) == ev_bool)


extern char *eval_tag_name[];



typedef struct _valaddr {
	ENUM type_tag type;
	struct _value *val;
} VALADDR;


typedef struct _pexpr {
	struct _cblock *cblock;
	struct _expr *expr;
} PEXPR;


typedef struct _evalelm {
	ENUM eval_tag tag;
	union {
		ENUM expr_tag op;
		long ival;
		double rval;
		int bool;
		char *string;
		struct _valaddr valaddr;	/* a typed value cell */
		struct _symtab *sym;		/* label / switch / proc */
		struct _pexpr pexpr;		/* parameter passing */
	} u;
	char *source;
	int lineno;
} EVALELM;

extern int evalst_siz;
extern int evalst_idx;
extern EVALELM *evalst;

#define TOP_EVALST	(evalst + evalst_idx - 1)
#define POP_EVALST	(evalst + --evalst_idx)
#define	CLEAR_EVALST	evalst_idx = 0

#define CHECK_EVALST \
	if (evalst_idx + 10 > evalst_siz) expand_evalst ()

#ifdef __GNUC__
#define PUSH_EVALST(so,li,tt) \
	({EVALELM *_ev; CHECK_EVALST; _ev = evalst + evalst_idx; \
	  _ev->tag = tt, _ev->source = so; _ev->lineno = li; \
	  evalst_idx++; _ev; })
#else
#define PUSH_EVALST(so,li,tt) \
	(((evalst_idx + 10 > evalst_siz) ? (expand_evalst (), 0) : 0), \
	 (evalst+evalst_idx)->tag = tt, \
	 (evalst+evalst_idx)->source = so, \
	 (evalst+evalst_idx)->lineno = li, \
	 (evalst + evalst_idx++))
#endif


extern void init_evalst P((void));
extern void expand_evalst P((void));
extern struct _evalelm *push_evalst P((char *, int, enum eval_tag));
extern void dump_evalst P((char *));
extern void do_unop P((enum expr_tag));
extern void do_binop P((enum expr_tag));

#define DO_DEREF(s, n) \
	if ((TOP_EVALST)->tag == ev_valaddr) do_deref (s, n)
extern void do_deref P((char *, int));

extern void store_data ();
extern void do_eval_sign P((void));


extern void do_eval_pexpr P((struct _pexpr *));
extern void do_eval_expr P((struct _expr *));

extern void do_eval_lhelm P((struct _lhelm *));
extern void do_push_lhelm P((struct _lhelm *));


#undef P

#endif /* EVAL_H_HOOK */
