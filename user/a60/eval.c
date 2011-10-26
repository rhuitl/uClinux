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
 * eval.h:						aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * evaluation of binary and unary expressions is still done here.
 * code for storing an eval-stack element to a data-cell of an
 * activation.
 */

#include "comm.h"
#include "a60.h"
#include "tree.h"
#include "util.h"
#include "run.h"
#include "conv.h"
#include "eval.h"

/* 
 * the evaluation stack. 
 */
int evalst_siz = 0;
int evalst_idx = 0;
EVALELM *evalst;


char *eval_tag_name[] = {
	"none",
	"integer",
	"real",
	"boolean",
	"unop",
	"binop",
	"valaddr",
	"label",
	"switch",
	"proc",
	"string",
	"expr",
	"symbol",
	"last_eval_tag_name"
};


void
init_evalst ()
{
	evalst_siz = 20;
	evalst_idx = 0;
	evalst = NTALLOC(evalst_siz, EVALELM);
}


void
expand_evalst ()
{
	evalst_siz += 20;
#ifdef DEBUG
	if (do_debug)
		printf ("*** evalstack extended to %ld elms\n",
			(long) evalst_siz);
#endif /* DEBUG */
	evalst = NTREALLOC (evalst, evalst_siz, EVALELM);
}


/*
 * execute an unary operator; NOT or NEG.
 * argument is on top-of-evalstack and result is returned is the same
 * cell. 
 */

void
do_unop (op)
ENUM expr_tag op;
{
	EVALELM *ev;
	
	ev = TOP_EVALST;

	if (op == e_op_not) {
		if (ev->tag == ev_bool)
			ev->u.bool = ! ev->u.bool;
		else {
			a60_error (ev->source, ev->lineno,
				   "invalid type `%s' for NOT\n",
				   eval_tag_name[ev->tag]);
			xabort ("runtime error");
		}
	}
	else if (op == e_op_neg) {
		if (ev->tag == ev_ival)
			ev->u.ival = - ev->u.ival;
		else if (ev->tag == ev_rval)
			ev->u.rval = - ev->u.rval;
		else {
			a60_error (ev->source, ev->lineno,
				   "invalid type `%s' for unary `-'\n",
				   eval_tag_name[ev->tag]);
			xabort ("runtime error");
		}
	}
	else {
		a60_error (ev->source, ev->lineno, 
			   "INTERNAL: do_unop: unknown op %d\n", op);
		xabort ("INTERNAL");
	}
}


/*
 * handle binop-runtime-error; print message and abort.
 */

static void
bop_err (ev1, ev2, s)
EVALELM *ev1, *ev2;
char *s;
{
	a60_error (ev1->source, ev1->lineno,
		   "cannot evaluate `%s' %s `%s'\n",
		   eval_tag_name[ev1->tag], s,
		   eval_tag_name[ev2->tag]);
	xabort ("runtime error");
}


/*
 * all the binary op's; result must be in ev2.
 */

static void
eval_do_plus (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival)
			ev2->u.ival += ev1->u.ival;
		else if (ev2->tag == ev_rval)
			ev2->u.rval += IVAL2RVAL(ev1->u.ival);
		else
			bop_err (ev1, ev2, "+");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.rval = IVAL2RVAL(ev2->u.ival) + ev1->u.rval;
			ev2->tag = ev_rval;
		}
		else if (ev2->tag == ev_rval)
			ev2->u.rval += ev1->u.rval;
		else
			bop_err (ev1, ev2, "+");
	}
	else
		bop_err (ev1, ev2, "+");
}


static void
eval_do_minus (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival)
			ev2->u.ival = ev1->u.ival - ev2->u.ival;
		else if (ev2->tag == ev_rval)
			ev2->u.rval = IVAL2RVAL(ev1->u.ival) - ev2->u.rval;
		else
			bop_err (ev1, ev2, "-");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.rval = ev1->u.rval - IVAL2RVAL(ev2->u.ival);
			ev2->tag = ev_rval;
		}
		else if (ev2->tag == ev_rval)
			ev2->u.rval = ev1->u.rval - ev2->u.rval;
		else
			bop_err (ev1, ev2, "-");
	}
	else
		bop_err (ev1, ev2, "-");
}


static void
eval_do_times (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival)
			ev2->u.ival *= ev1->u.ival;
		else if (ev2->tag == ev_rval)
			ev2->u.rval *= IVAL2RVAL(ev1->u.ival);
		else
			bop_err (ev1, ev2, "*");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.rval = IVAL2RVAL(ev2->u.ival) * ev1->u.rval;
			ev2->tag = ev_rval;
		}
		else if (ev2->tag == ev_rval)
			ev2->u.rval *= ev1->u.rval;
		else
			bop_err (ev1, ev2, "*");
	}
	else
		bop_err (ev1, ev2, "*");
}


static void
eval_do_rdiv (ev1, ev2)
EVALELM *ev1, *ev2;
{
	double x = 0, y = 0;

	if (ev1->tag == ev_ival)
		x = IVAL2RVAL(ev1->u.ival);
	else if (ev1->tag == ev_rval)
		x = ev1->u.rval;
	else
		bop_err (ev1, ev2, "/");

	if (ev2->tag == ev_ival)
		y = IVAL2RVAL(ev2->u.ival);
	else if (ev2->tag == ev_rval)
		y = ev2->u.rval;
	else
		bop_err (ev1, ev2, "/");

	if (y == 0.0) {
		a60_error (ev2->source, ev2->lineno, 
			   "Oops - divison by zero\n");
		xabort ("runtime error");
	}

	ev2->tag = ev_rval;
	ev2->u.rval = x / y;
}


static void
eval_do_idiv (ev1, ev2)
EVALELM *ev1, *ev2;
{
	long x = 0, y = 0;

	if (ev1->tag == ev_ival)
		x = ev1->u.ival;
	else if (ev1->tag == ev_rval)
		x = RVAL2IVAL(ev1->u.rval);
	else
		bop_err (ev1, ev2, "DIV");

	if (ev2->tag == ev_ival)
		y = ev2->u.ival;
	else if (ev2->tag == ev_rval)
		y = RVAL2IVAL(ev2->u.rval);
	else
		bop_err (ev1, ev2, "DIV");

	if (y == 0) {
		a60_error (ev2->source, ev2->lineno,
			   "Oops - divison by zero\n");
		xabort ("runtime error");
	}

	ev2->tag = ev_ival;
	ev2->u.ival = x / y;
}


static void
eval_do_pow (ev1, ev2)
EVALELM *ev1, *ev2;
{
	/*
	 * should be better done; (and: not fully tested)...
	 */
	
	if (ev2->tag == ev_ival) {
		if (ev2->u.ival > 0) {
			if (ev1->tag == ev_ival) {
				ev2->tag = ev_ival;
				/*
				 * should be a*a*a...*a
				 * hopefully exact enough so...
				 */
				ev2->u.ival = RVAL2IVAL(exp ((double) 
					ev2->u.ival * log ((double)
					ev1->u.ival)));
			}
			else if (ev1->tag == ev_rval) {
				ev2->tag = ev_rval;
				ev2->u.rval = exp ((double) 
					ev2->u.ival * log ((double)
					ev1->u.rval));
			}
			else
				bop_err (ev1, ev2, "POW");
		}
		else if (ev2->u.ival == 0) {
			if (ev1->tag == ev_ival) {
				if (ev1->u.ival != 0) {
					ev2->tag = ev_ival;
					ev2->u.ival = 1;
				}
				else {
					/* UNDEFINED */
					ev2->tag = ev_rval;
					ev2->u.ival = 0.0;
					a60_error (ev1->source, ev1->lineno,
					"undefined result in POW ...\n");
				}
			}
			else if (ev1->tag == ev_rval) {
				if (ev1->u.rval != 0) {
					ev2->tag = ev_rval;
					ev2->u.rval = 1.0;
				}
				else {
					/* UNDEFINED */
					ev2->tag = ev_rval;
					ev2->u.ival = 0.0;
					a60_error (ev1->source, ev1->lineno,
					"undefined result in POW ...\n");
				}
			}
			else
				bop_err (ev1, ev2, "POW");
		}
		else if (ev2->u.ival < 0) {
			if (ev1->tag == ev_ival) {
				if (ev1->u.ival != 0) {
					ev2->tag = ev_rval;
					ev2->u.rval = 1.0 / (exp ((double) 
						ev2->u.ival * log ((double)
						ev1->u.ival)));
				}
				else {
					/* UNDEFINED */
					ev2->tag = ev_rval;
					ev2->u.ival = 0.0;
					a60_error (ev1->source, ev1->lineno,
					"undefined result in POW ...\n");
				}
			}
			else if (ev1->tag == ev_rval) {
				if (ev1->u.rval != 0.0) {
					ev2->tag = ev_rval;
					ev2->u.rval = 1.0 / (exp ((double) 
						ev2->u.rval * log ((double)
						ev1->u.ival)));
				}
				else {
					/* UNDEFINED */
					ev2->tag = ev_rval;
					ev2->u.ival = 0.0;
					a60_error (ev1->source, ev1->lineno,
					"undefined result in POW ...\n");
				}
			}
			else
				bop_err (ev1, ev2, "POW");
		}
	}
	else if (ev2->tag == ev_rval) {
		if (ev1->tag == ev_ival) {
			if (ev1->u.ival > 0) {
				ev2->tag = ev_rval;
				ev2->u.rval = exp ((double) 
					ev2->u.rval * log ((double)
					ev1->u.ival));
			}
			else if (ev1->u.ival == 0) {
				if (ev2->u.rval > 0.0) {
					ev2->tag = ev_rval;
					ev2->u.rval = 0.0;
				}
				else {
					/* UNDEFINED */
					ev2->tag = ev_rval;
					ev2->u.ival = 0.0;
					a60_error (ev1->source, ev1->lineno,
					"undefined result in POW ...\n");
				}
			}
			else {
				/* UNDEFINED */
				ev2->tag = ev_rval;
				ev2->u.ival = 0.0;
				a60_error (ev1->source, ev1->lineno,
				"undefined result in POW ...\n");
			}
		}
		else if (ev1->tag == ev_rval) {
			if (ev1->u.rval > 0.0) {
				ev2->tag = ev_rval;
				ev2->u.rval = exp ((double) 
					ev2->u.rval * log ((double)
					ev1->u.rval));
			}
			else if (ev1->u.rval == 0.0) {
				if (ev2->u.rval > 0.0) {
					ev2->tag = ev_rval;
					ev2->u.rval = 0.0;
				}
				else {
					/* UNDEFINED */
					ev2->tag = ev_rval;
					ev2->u.ival = 0.0;
					a60_error (ev1->source, ev1->lineno,
					"undefined result in POW ...\n");
				}
			}
			else {
				/* UNDEFINED */
				ev2->tag = ev_rval;
				ev2->u.ival = 0.0;
				a60_error (ev1->source, ev1->lineno,
				"undefined result in POW ...\n");
			}
		}
		else 
			bop_err (ev1, ev2, "POW");
	}
	else 
		bop_err (ev1, ev2, "POW");
}


static void
eval_do_and (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_bool && ev2->tag == ev_bool)
		ev2->u.bool = ev1->u.bool && ev2->u.bool;
	else
		bop_err (ev1, ev2, "AND");
}


static void
eval_do_or (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_bool && ev2->tag == ev_bool)
		ev2->u.bool = ev1->u.bool || ev2->u.bool;
	else
		bop_err (ev1, ev2, "OR");
}


static void
eval_do_equiv (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_bool && ev2->tag == ev_bool)
		ev2->u.bool = ev1->u.bool == ev2->u.bool;
	else
		bop_err (ev1, ev2, "AND");
}


static void
eval_do_impl (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_bool && ev2->tag == ev_bool)
		ev2->u.bool = ! ev1->u.bool || ev2->u.bool;
	else
		bop_err (ev1, ev2, "AND");
}


static void
eval_do_less (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.ival < ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = (double) ev1->u.ival < ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "LESS");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.rval < (double) ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = ev1->u.rval < ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "LESS");
	}
	else
		bop_err (ev1, ev2, "LESS");

	ev2->tag = ev_bool;
}


static void
eval_do_notgreater (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.ival <= ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = (double) ev1->u.ival <= ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "NOTGREATER");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.rval <= (double) ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = ev1->u.rval <= ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "NOTGREATER");
	}
	else
		bop_err (ev1, ev2, "NOTGREATER");

	ev2->tag = ev_bool;
}


static void
eval_do_equal (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.ival == ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = (double) ev1->u.ival == ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "EQUAL");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.rval == (double) ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = ev1->u.rval == ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "EQUAL");
	}
	else
		bop_err (ev1, ev2, "EQUAL");

	ev2->tag = ev_bool;
}


static void
eval_do_notless (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.ival >= ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = (double) ev1->u.ival >= ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "NOTLESS");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.rval >= (double) ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = ev1->u.rval >= ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "NOTLESS");
	}
	else
		bop_err (ev1, ev2, "NOTLESS");

	ev2->tag = ev_bool;
}


static void
eval_do_greater (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.ival > ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = (double) ev1->u.ival > ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "GREATER");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.rval > (double) ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = ev1->u.rval > ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "GREATER");
	}
	else
		bop_err (ev1, ev2, "GREATER");

	ev2->tag = ev_bool;
}


static void
eval_do_notequal (ev1, ev2)
EVALELM *ev1, *ev2;
{
	if (ev1->tag == ev_ival) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.ival != ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = (double) ev1->u.ival != ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "NOTEQUAL");
	}
	else if (ev1->tag == ev_rval) {
		if (ev2->tag == ev_ival) {
			ev2->u.bool = ev1->u.rval != (double) ev2->u.ival;
		}
		else if (ev2->tag == ev_rval) {
			ev2->u.bool = ev1->u.rval != ev2->u.rval;
		}
		else
			bop_err (ev1, ev2, "NOTEQUAL");
	}
	else
		bop_err (ev1, ev2, "NOTEQUAL");

	ev2->tag = ev_bool;
}


/*
 * all the binop's:
 */

void
do_binop (op)
ENUM expr_tag op;
{
	EVALELM *ev1, *ev2;
	
	ev1 = POP_EVALST;
	ev2 = TOP_EVALST;
	
	switch (op) {

	case e_op_plus:
		eval_do_plus (ev1, ev2);
		break;
	case e_op_minus:
		eval_do_minus (ev1, ev2);
		break;
	case e_op_times:
		eval_do_times (ev1, ev2);
		break;
	case e_op_rdiv:
		eval_do_rdiv (ev1, ev2);
		break;
	case e_op_idiv:
		eval_do_idiv (ev1, ev2);
		break;
	case e_op_pow:
		eval_do_pow (ev1, ev2);
		break;
	case e_op_and:
		eval_do_and (ev1, ev2);
		break;
	case e_op_or:
		eval_do_or (ev1, ev2);
		break;
	case e_op_equiv:
		eval_do_equiv (ev1, ev2);
		break;
	case e_op_impl:
		eval_do_impl (ev1, ev2);
		break;
	case e_op_less:
		eval_do_less (ev1, ev2);
		break;
	case e_op_notgreater:
		eval_do_notgreater (ev1, ev2);
		break;
	case e_op_equal:
		eval_do_equal (ev1, ev2);
		break;
	case e_op_notless:
		eval_do_notless (ev1, ev2);
		break;
	case e_op_greater:
		eval_do_greater (ev1, ev2);
		break;
	case e_op_notequal:
		eval_do_notequal (ev1, ev2);
		break;

	default:
		a60_error ("INTERNAL", 0,
			   "INTERNAL: do_binop: unknown op %d\n", op);
	}
}


void
do_deref (source, lineno)
char *source;
int lineno;
{
	EVALELM *ee, ev;
	VALUE *val;
	ENUM type_tag type;

	if (TOP_EVALST->tag != ev_valaddr)
		return;

	ev = * POP_EVALST;

	val = ev.u.valaddr.val;
	type = BASE_TYPE(ev.u.valaddr.type);
	
	if (! val->valid) {
		a60_error (source, lineno, "uninitialized value\n");
		xabort ("runtime error");
	}
	else {
		if (type == ty_integer) {
			ee = PUSH_EVALST(source, lineno, ev_ival);
			ee->u.ival = ev.u.valaddr.val->u.ival;
		}
		else if (type == ty_real) {
			ee = PUSH_EVALST(source, lineno, ev_rval);
			ee->u.rval = ev.u.valaddr.val->u.rval;
		}
		else if (type == ty_bool) {
			ee = PUSH_EVALST(source, lineno, ev_bool);
			ee->u.bool = ev.u.valaddr.val->u.ival != 0;
		}
		else
			xabort ("deref: bad type!");
	}
}


/*
 * store an array by_value:
 */

static void
store_arr (ev, act, sym)
EVALELM *ev;
ACTIV *act;
SYMTAB *sym;
{
	ENUM type_tag o_type, exp_type;
	DATA *data = act->data;
	ACTIV *o_act;
	CBLOCK *cb;
	long i, siz;
	VALUE *val, *newval, *oval;

	if (ev->tag != ev_sym || ! TIS_ARR(ev->u.sym->type)) {
		a60_error (ev->source, ev->lineno,
	   "actual parameter does not match formal (array ident expected)\n");
		xabort ("runtime error");
	}

	o_type = TAR_BASE(ev->u.sym->type);
	exp_type = TAR_BASE(sym->type);

#ifdef DEBUG
	if (do_debug)
		printf ("* store_arr: `%s' -> `%s'...\n",
			type_tag_name[o_type], type_tag_name[exp_type]);
#endif /* DEBUG */

	if (o_type != exp_type
	    && (! TIS_NUM(o_type) || ! TIS_NUM(exp_type))) {
		a60_error (ev->source, ev->lineno,
	   "actual parameter does not match formal (bad type)\n");
		xabort ("runtime error");
	}

	cb = act_cblock;
	while (cb && cb->block != ev->u.sym->block)
		cb = cb->next;

	if (!cb || ! cb->activ)
		xabort ("INTERNAL: store_arr: no activation!");

	o_act = cb->activ + ev->u.sym->actidx;
	act->arract = o_act->arract;

	siz = o_act->arract->size;
	
	oval = o_act->data->u.val;
	newval = NTALLOC(siz, VALUE);
	for (val=newval, i=0; i<siz; i++, val++, oval++) {
		
		if (o_type == exp_type)
			*val = *oval;
		else if (o_type == ty_real && exp_type == ty_integer) {
			if (oval->valid)
				val->u.ival = RVAL2IVAL(oval->u.rval);
		}
		else if (o_type == ty_integer && exp_type == ty_real) {
			if (oval->valid)
				val->u.rval = IVAL2RVAL(oval->u.ival);
		}
		else {
			a60_error (ev->source, ev->lineno,
	   "cannot convert array type `%s' to `%s'.\n",
			   type_tag_name[o_type], type_tag_name[exp_type]);
			xabort ("runtime error");
		}
		val->valid = oval->valid;
	}
	data->u.val = newval;

#ifdef DEBUG
	if (do_debug)
		printf ("* passed by value `%s' -> `%s' (%ld elms)\n",
			ev->u.sym->name, sym->name, siz);
#endif /* DEBUG */
}



/*
 * copy the eval-elm to a symbol data space (activation).
 * used when calling by-value.
 */

void
store_data (ev, act, sym)
EVALELM *ev;
ACTIV *act;
SYMTAB *sym;
{
	int error = 0;
	DATA *data = act->data;
	
#ifdef DEBUG
	if (do_debug)
		printf ("** store data: ev->tag: %s; sym->type: %s\n",
			eval_tag_name[ev->tag], type_tag_name[sym->type]);
#endif /* DEBUG */

	if (TIS_ARR(sym->type)) {
		store_arr (ev, act, sym);
		return;
	}

	/**** type check ****/

	switch (ev->tag) {
	case ev_ival:
		if (sym->type == ty_integer) {
			data->u.val = TALLOC (VALUE);
			data->u.val->u.ival = ev->u.ival;
		}
		else if (sym->type == ty_real) {
			data->u.val = TALLOC (VALUE);
			data->u.val->u.rval = IVAL2RVAL(ev->u.ival);
		}
		else
			error = 1;
		break;
	case ev_rval:
		if (sym->type == ty_real) {
			data->u.val = TALLOC (VALUE);
			data->u.val->u.rval = ev->u.rval;
		}
		else if (sym->type == ty_integer) {
			data->u.val = TALLOC (VALUE);
			data->u.val->u.ival = RVAL2IVAL(ev->u.rval);
		}
		else
			error = 1;
		break;
	case ev_bool:
		if (sym->type == ty_bool) {
			data->u.val = TALLOC (VALUE);
			data->u.val->u.ival = ev->u.bool;
		}
		else
			error = 1;
		break;
	case ev_string:
		if (sym->type == ty_string) {
			data->u.val = TALLOC (VALUE);
			data->u.val->u.string = ev->u.string;
		}
		else
			error = 1;
		break;
	default:
		error = 1;
		break;
	}

	if (error) {
		a60_error (ev->source, ev->lineno, 
			   "illegal parameter type %s; %s expected\n",
			   eval_tag_name[ev->tag], type_tag_name[sym->type]);
		xabort ("runtime error");
	}

	data->u.val->valid = 1;
}


/*
 * calculate the sign() func. for top_evalst. use top element for
 * returning the value and use the given type.
 * (only used in the while-loop)
 */

void
do_eval_sign ()
{
	EVALELM *ev;
	
	ev = TOP_EVALST;

	if (ev->tag == ev_ival) {
		if (ev->u.ival > 0)
			ev->u.ival = 1;
		else if  (ev->u.ival < 0)
			ev->u.ival = -1;
		else
			ev->u.ival = 0;
	}
	else if (ev->tag == ev_rval) {
		if (ev->u.rval > 0.0)
			ev->u.rval = 1.0;
		else if  (ev->u.rval < 0)
			ev->u.rval = -1.0;
		else
			ev->u.rval = 0.0;
	}
	else {
		a60_error (ev->source, ev->lineno, 
			   "invalid type `%s' for SIGN\n",
			   eval_tag_name[ev->tag]);
		xabort ("runtime error");
	}
}


#ifdef DEBUG

/*
 * dump the evaluation stack.
 */

void
dump_evalst (s)
char *s;
{
	int i;
	EVALELM *ev;

	printf ("------ eval stack (%s) -------\n", s);
	
	for (i=0; i < evalst_idx; i++) {
		ev = evalst+i;
		printf (" %s", eval_tag_name[ev->tag]);
		if (ev->tag == ev_ival)
			printf (": %ld\n", ev->u.ival);
		else if (ev->tag == ev_rval)
			printf (": %g\n", ev->u.rval);
		else if (ev->tag == ev_bool)
			printf (": %s\n", (ev->u.bool) ? "TRUE" : "FALSE");
		else if (ev->tag == ev_unop || ev->tag == ev_binop)
			printf (": %s\n", expr_tag_name[ev->u.op]);
		else if (ev->tag == ev_valaddr)
			printf (": (addr 0x%lx) type %s\n", 
				(long) & ev->u.valaddr, 
				type_tag_name[ev->u.valaddr.type]);
		else if (ev->tag == ev_label
			 || ev->tag == ev_switch
			 || ev->tag == ev_proc)
			printf (": (sym `%s'; addr 0x%lx)\n", 
				(char *) ev->u.sym->name,
				(long) ev->u.sym);
		else
			printf ("\n");
	}
	printf ("\n");
}

#endif /* DEBUG */

/* end of eval.c */
