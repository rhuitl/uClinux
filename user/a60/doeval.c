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
 * doeval.c:						oct '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * here is some code about runtime evaluation; it is mixed with 
 * eval.c and used from run.c
 */

#include "comm.h"
#include "a60.h"
#include "util.h"
#include "conv.h"
#include "run.h"
#include "eval.h"


/*
 * evaluate a switch expression.
 */

static void
do_eval_switchexpr (sym, ex)
SYMTAB *sym;
EXPR *ex;
{
	long idx = 0;
	SWACT *swact;
	EVALELM ev, *evp;

#ifdef DEBUG
	if (do_debug)
		printf ("** do_eval_switchexpr: sym is `%s' ...\n", sym->name);
#endif /* DEBUG */

	if (sym->tag == s_byname)
		xabort ("INTERNAL: do_eval_switchexpr: s_byname");

	swact = get_swact (sym);
	if (! swact) {
		a60_error (ex->source, ex->lineno,
			   "uninitialized switch list (symbol is `%s').\n",
			   sym->name);
		xabort ("runtime error");
	}

	/* now eval the index: */
	do_eval_expr (ex);
	DO_DEREF(ex->source, ex->lineno);
	ev = * POP_EVALST;
	if (ev.tag == ev_ival)
		idx = ev.u.ival;
	else if (ev.tag == ev_rval)
		idx = RVAL2IVAL (ev.u.rval);
	else {
		a60_error (ex->source, ex->lineno,
   "subscript of designational expression must be of numerical type.\n");
		a60_error (ex->source, ex->lineno,
			   "(but the type is `%s').\n", 
			   eval_tag_name [ev.tag]);
		xabort ("runtime error");
	}

#ifdef DEBUG
	if (do_debug)
		printf ("** do_eval_switchexpr: idx is %ld.\n", idx);
#endif /* DEBUG */
	
	if (idx < 1 || idx > swact->nelm) {
		/*
		 * an undefined design. expr. leads to a dummy
		 */

		/* +++++ add runtime warning +++++ */

#ifdef DEBUG
		if (do_debug)
			printf ("** index out of range: dummy.\n");
#endif /* DEBUG */

		evp = PUSH_EVALST(ex->source, ex->lineno, ev_label);
		evp->u.sym = (SYMTAB *) 0;
	}
	else {
		evp = PUSH_EVALST(ex->source, ex->lineno, ev_label);
		/* ***** 16 bit idx ***** */
		evp->u.sym = swact->targs [(int) idx - 1];
	}
}


static void
do_eval_arrval (lhelm)
LHELM *lhelm;
{
	SYMTAB *sym = lhelm->sym;
	MINDEX *mindex;
	CBLOCK *cb;
	ACTIV *act;
	ACT_BOUND *bound;
	EVALELM *ev;
	long idx = 0;
#ifdef MEMORY_STATISTICS
	DO_STACK_STAT;
#endif

	mindex = lhelm->mindex;
	if (! mindex)
		xabort ("INTERNAL: do_eval_arrval: no mindex");

	while (sym->tag == s_byname) {
		CBLOCK *cb = act_cblock;
		ACTIV *act;
#ifdef DEBUG
		if (do_debug)
			printf ("* do_eval_arrval: sym is `%s'...\n",
				sym->name);
#endif /* DEBUG */
		while (cb->block != sym->block)
			cb = cb->next;
		act = cb->activ + sym->actidx;
		if (act->data->u.pexpr.expr->tag != e_symbol)
			xabort ("INTERNAL: do_eval_arrval: no symbol");
		sym = act->data->u.pexpr.expr->u.lhelm->sym;
	}
	
#ifdef DEBUG
	if (do_debug) 
		printf ("* do_eval_arrval: sym is `%s' !\n", sym->name);
#endif /* DEBUG */

	if (sym->type == ty_switch) {
		/*
		 * got you: this is parsed as an array access, but
		 * actual ans des-expression.
		 * its a bad hack - yeh.
		 */

#ifdef DEBUG
		if (do_debug)
			printf ("** do_eval_arrval: is a switch ...\n");
#endif /* DEBUG */

		do_eval_switchexpr (sym, mindex->expr);
		return;
	}

	if (! TIS_ARR(sym->type)) {
		a60_error (lhelm->source, lhelm->lineno,
			   "not an array: `%s'\n", sym->name);
		xabort ("runtime error");
	}

	cb = act_cblock;
	while (cb->block != sym->block)
		cb = cb->next;
	act = cb->activ + sym->actidx;
	/*
	 * this can happen, if the array declaration is interrupted by
	 * an goto :-)
	 */
	if (! act || ! act->arract) {
		a60_error (lhelm->source, lhelm->lineno,
			   "uninitialized array\n");
		xabort ("runtime error");
	}
	
	bound = act->arract->act_bound;

	while (mindex) {
		do_eval_expr (mindex->expr);
		DO_DEREF(mindex->expr->source, mindex->expr->lineno);
		ev = POP_EVALST;

		if (ev->tag == ev_rval) {
			ev->tag = ev_ival;
			ev->u.ival = RVAL2IVAL(ev->u.rval);
		}
		else if (ev->tag != ev_ival) {
			a60_error (ev->source, ev->lineno,
		   "array index must be of numerical type (found `%s')\n",
				   eval_tag_name[ev->tag]);
			xabort ("runtime error");
		}

		if (ev->u.ival < bound->from
		    || ev->u.ival > bound->til) {
			a60_error (ev->source, ev->lineno,
	"index not in bound; index is %ld, bounds are [%ld : %ld]\n",
				   ev->u.ival, bound->from, bound->til);
			xabort ("runtime error");
		}

		idx = idx + (ev->u.ival - bound->from) * bound->mpl;
		
		mindex = mindex->next;
		bound = bound->next;
	}

#ifdef DEBUG
	if (do_debug)
		printf ("* do_eval_arrval: idx is %ld.\n", idx);
#endif /* DEBUG */

	push_valaddr (lhelm->source, lhelm->lineno, sym, idx);
}



void
do_push_lhelm (lhelm)
LHELM *lhelm;
{
	SYMTAB *sym = lhelm->sym;


	if (lhelm->mindex) {
		do_eval_arrval (lhelm);
		return;
	}

#ifdef DEBUG
	if (do_debug)
		printf ("* do_push_lhelm: sym is `%s'...\n", sym->name);
#endif /* DEBUG */

	while (sym->tag == s_byname) {
		CBLOCK *cb = act_cblock;
		ACTIV *act;
		ENUM expr_tag tag;
		while (cb->block != sym->block)
			cb = cb->next;
		act = cb->activ + sym->actidx;
		tag = act->data->u.pexpr.expr->tag;
		if (tag != e_symbol && tag != e_fcall) {
			a60_error (lhelm->source, lhelm->lineno,
				"no valid lefthand type (type is `%s')\n",
				 sym->name);
			xabort ("runtime error");
		}
		if (act->data->u.pexpr.expr->u.lhelm->mindex) {
			do_eval_arrval (act->data->u.pexpr.expr->u.lhelm);
			return;
		}
		sym = act->data->u.pexpr.expr->u.lhelm->sym;
	}


#ifdef DEBUG
	if (do_debug)
		printf ("* do_push_lhelm: sym is `%s' !\n", sym->name);
#endif /* DEBUG */

	if (! TIS_SVALT(sym->type)) {
		a60_error (lhelm->source, lhelm->lineno,
		   "illegal lefthand side (type is `%s')\n",
			   type_tag_name[sym->type]);
		xabort ("runtime error");
	}

	push_valaddr (lhelm->source, lhelm->lineno, sym, (long) 0);
}



void
do_eval_lhelm (lhelm)
LHELM *lhelm;
{
	SYMTAB *sym = lhelm->sym;
	ENUM expr_tag tag;
#ifdef MEMORY_STATISTICS
	DO_STACK_STAT;
#endif

	if (lhelm->mindex) {
		do_eval_arrval (lhelm);
		return;
	}

#ifdef DEBUG
	if (do_debug)
		printf ("* do_eval_lhelm: sym is `%s'...\n", sym->name);
#endif /* DEBUG */

	if (sym->tag == s_byname) {
		CBLOCK *cb = act_cblock;
		ACTIV *act;
		while (cb->block != sym->block)
			cb = cb->next;
		act = cb->activ + sym->actidx;
		tag = act->data->u.pexpr.expr->tag;
		if (tag != e_symbol) {
			do_eval_pexpr (& act->data->u.pexpr);
			return;
		}
		do_eval_pexpr (& act->data->u.pexpr);
		return;
	}

#ifdef DEBUG
	if (do_debug)
		printf ("* do_eval_lhelm: sym is `%s' !\n", sym->name);
#endif /* DEBUG */

	if (TIS_BASET(sym->type) || TIS_FUNC(sym->type)) {
		push_valaddr (lhelm->source, lhelm->lineno, sym, (long) 0);
	}
	else if (TIS_SPECT(sym->type)) {
		push_spec (lhelm->source, lhelm->lineno, sym);
	}
	else if (TIS_ARR(sym->type)) {
		push_spec (lhelm->source, lhelm->lineno, sym);
	}
	else
		a60_error (lhelm->source, lhelm->lineno,
		   "INTERNAL: do_eval_lhelm: bad sym type `%s'\n", 
			   sym_tag_name[sym->type]);
}


void
do_eval_expr (ex)
EXPR *ex;
{
	ENUM expr_tag tag = ex->tag;
	EVALELM *ev, top_ev;
	SYMTAB *sym;
#ifdef MEMORY_STATISTICS
	DO_STACK_STAT;
#endif

#ifdef DEBUG
	if (do_debug)
		printf ("** do_eval_expr: have here a `%s' (type is `%s').\n",
			expr_tag_name [tag], type_tag_name [ex->type]);
#endif /* DEBUG */

	if (tag == e_switch) {
		sym = ex->u.eswitch->sym;
		while (sym->tag == s_byname) {

			while (sym->tag == s_byname) {
				CBLOCK *cb = act_cblock;
				ACTIV *act;
#ifdef DEBUG
				if (do_debug)
					printf (
			"* do_eval_expr: switch sym is `%s'...\n",
						sym->name);
#endif /* DEBUG */
				while (cb->block != sym->block)
					cb = cb->next;
				act = cb->activ + sym->actidx;
				if (act->data->u.pexpr.expr->tag != e_symbol)
					xabort (
				"INTERNAL: do_eval_expr: switch: no symbol");
				sym = act->data->u.pexpr.expr->u.lhelm->sym;
#ifdef DEBUG
				if (do_debug)
					printf (
                        "* do_eval_expr: now it is  `%s'...\n",
						sym->name);
#endif /* DEBUG */
			}
		}
		do_eval_switchexpr (sym, ex->u.eswitch->expr);
		return;
	}
	else if (tag == e_label) {
		sym = ex->u.label;
		while (sym->tag == s_byname) {
			DATA *data;

#ifdef DEBUG
			if (do_debug)
				printf ("** label with s_byname (%s)...\n",
					sym->name);
#endif /* DEBUG */

			data = get_sym_data (sym);
			do_eval_pexpr (&(data->u.pexpr));
			return;
		}
		ev = PUSH_EVALST(ex->source, ex->lineno, ev_label);
		ev->u.sym = sym;
	}
	else if (tag == e_symbol) {
		/*
		 * hmmm - may be its a numerical expression or it is a
		 * designational expression...
		 */
		do_eval_lhelm (ex->u.lhelm);
	}
	else if (tag == e_fcall) {
		if (trace)
			printf ("line %d: executing func call (`%s')\n",
				ex->lineno, ex->u.lhelm->sym->name);

		sym = ex->u.lhelm->sym;
		while ((TIS_PROC(sym->type) || sym->type == ty_unknown) 
		       && sym->tag == s_byname) {
			DATA *data;
			EVALELM ev;
#ifdef DEBUG
			if (do_debug)
				printf ("** call with func parm (%s):\n",
					sym->name);
#endif /* DEBUG */
			data = get_sym_data (sym);
			push_spec_pexpr (&(data->u.pexpr));
			ev = * POP_EVALST;
			sym = ev.u.sym;
#ifdef DEBUG
			if (do_debug)
				printf ("   -> now it is func parm (%s).\n",
					sym->name);
#endif /* DEBUG */
		}

		if (! TIS_FUNC(sym->type) && sym->tag == s_defined) {
			a60_error (ex->source, ex->lineno,
		   "must return a value (`%s')\n",
				   ex->u.lhelm->sym->name);
			xabort ("runtime error");
		}

		exec_fcall (ex->source, ex->lineno,
			    sym, ex->u.lhelm->u.fcall);
	}
	else if (tag == e_ival) {
		ev = PUSH_EVALST(ex->source, ex->lineno, ev_ival);
		ev->u.ival = ex->u.ival;
	}
	else if (tag == e_rval) {
		ev = PUSH_EVALST(ex->source, ex->lineno, ev_rval);
		ev->u.rval = ex->u.rval;
	}
	else if (tag == e_bool) {
		ev = PUSH_EVALST(ex->source, ex->lineno, ev_bool);
		ev->u.bool = ex->u.bool;
	}
	else if (tag == e_string) {
		ev = PUSH_EVALST(ex->source, ex->lineno, ev_string);
		ev->u.string = ex->u.string;
	}
	else if (EIS_UNEXP(tag)) {
		do_eval_expr (ex->u.expr[0]);
		DO_DEREF(ex->source, ex->lineno);
		do_unop (tag);
	}
	else if (EIS_BINEXP(tag)) {
		do_eval_expr (ex->u.expr[1]);
		DO_DEREF(ex->source, ex->lineno);
		do_eval_expr (ex->u.expr[0]);
		DO_DEREF(ex->source, ex->lineno);
		do_binop (tag);
	}
	else if (tag == e_condexpr) {
		do_eval_expr (ex->u.expr[0]);
		DO_DEREF(ex->source, ex->lineno);
		top_ev = * POP_EVALST;
		if (top_ev.tag != ev_bool)
			a60_error ("INTERNAL", 0, "INTERNAL: No Bool!\n");
		if (top_ev.u.bool)
			do_eval_expr (ex->u.expr[1]);
		else
			do_eval_expr (ex->u.expr[2]);
	}
	else if (EIS_NOP(tag)) {
		do_eval_expr (ex->u.expr[0]);
	}
	else {
		a60_error (ex->source, ex->lineno,
			   "INTERNAL: do_eval_expr: unknown expr_tag `%s'\n",
			   expr_tag_name[tag]);
		xabort ("INTERNAL error");
	}
}


void
do_eval_pexpr (pex)
PEXPR *pex;
{
	if (pex->cblock)
		push_cblock (pex->cblock);

	do_eval_expr (pex->expr);

	if (pex->cblock)
		pop_cblock ();

}

/* end of doeval.c */
