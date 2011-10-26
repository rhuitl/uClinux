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
 * expr.h:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#ifndef EXPR_H_HOOK
#define EXPR_H_HOOK

#ifdef __STDC__
# define P(x)  x
#else
# define P(x)  ()
#endif


enum expr_tag {
	e_nop,
	e_symbol,
	e_string,
	e_label,
	e_switch,
	e_ival,
	e_rval,
	e_bool,
	e_fcall,		/* complete function */
	e_fparm,		/* function parameter */
	e_op_neg,
	e_op_not,
	e_op_plus,
	e_op_minus,
	e_op_times,
	e_op_rdiv,
	e_op_idiv,
	e_op_pow,
	e_op_and,
	e_op_or,
	e_op_equiv,
	e_op_impl,
	e_op_less,
	e_op_notgreater,
	e_op_equal,
	e_op_notless,
	e_op_greater,
	e_op_notequal,
	e_condexpr,
	E_LAST_EXPR_TAG
};

#define EIS_NOP(x) 	((x) == e_nop)
#define EIS_SYMBOL(x) 	((x) == e_symbol)
#define EIS_NUM(x) 	((x) >= e_ival && (x) <= e_rval)
#define EIS_BOOL(x) 	((x) == e_bool)
#define EIS_STRING(x) 	((x) == e_string)
#define EIS_PLAIN(x) 	(EIS_NUM(x) || EIS_BOOL(x))
#define EIS_UNEXP(x) 	((x) >= e_op_neg && (x) <= e_op_not)
#define EIS_BINEXP(x) 	((x) >= e_op_plus && (x) <= e_op_notequal)
#define EIS_ARITHEXP(x)	((x) >= e_op_plus && (x) <= e_op_pow)
#define EIS_BOOLEXP(x) 	((x) >= e_op_and && (x) <= e_op_impl)
#define EIS_RELEXP(x) 	((x) >= e_op_less && (x) <= e_op_notequal)

extern char *expr_tag_name[];

/*
 * switch at runtime; an identifier and the subscript expression.
 */

typedef struct _eswitch {
	struct _symtab *sym;		/* the switch identifier */
	struct _expr *expr;		/* the subscript expression */
} ESWITCH;


/*
 * the expression cell:
 */

typedef struct _expr {
	ENUM expr_tag tag;
	ENUM type_tag type;
	union {
		long ival;
		double rval;
		int bool;
		char *string;			/* string constant */
		struct _symtab *label;		/* label */
		struct _eswitch *eswitch;	/* switch */
		struct _lhelm *lhelm;		/* var, label, switch */
		struct _expr *expr[3];		/* unop, binop, if */
	} u;
	struct _expr *next;			/* list for fun-calls */
	char *source;
	int lineno;
} EXPR;


extern EXPR *new_expr P((enum expr_tag, enum type_tag));
extern EXPR *new_mix_expr P((EXPR *, enum expr_tag, EXPR *));
extern EXPR *new_xmix_expr P((EXPR *, enum expr_tag, EXPR *));
extern ESWITCH *new_eswitch P((char *, EXPR *));
extern void append_expr P((EXPR **, EXPR *));
extern void check_expr P((EXPR *));
extern void print_expr P((EXPR *));

#undef P

#endif /* EXPR_H_HOOK */
