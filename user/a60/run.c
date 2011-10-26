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
 * run.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 *
 * interpreter runtime code; here are mostly the things about
 * statements: assignments, loops ...
 */

#include "comm.h"
#include "a60.h"
#include "tree.h"
#include "util.h"
#include "eval.h"
#include "conv.h"
#include "run.h"


/*
 * next stmt to execute; see run_block() and run_goto for more about.
 */

static TREE *next_stmt = 0;


/*
 * forward: 
 */
static void do_this ();
static void leave_block ();


/*
 * the active block-scopes; on block entry, a scope is added, on
 * exit removed.
 */

static CBLOCK *rcblock;			/* root of scope's */
CBLOCK *act_cblock;			/* active scope */

/*
 * list of nested scopes:
 */

static CBELM *cbrelm = 0;		/* root of scope elms */


/*
 * open a new block.
 * (action when entering a block)
 */

static void
open_cblock (block)
BLOCK *block;
{
	CBLOCK *new;

#ifdef DEBUG
	if (do_debug)
		printf ("* setting new current block.\n");
#endif /* DEBUG */

	new = TALLOC (CBLOCK);
	new->block = block;
	new->activated = 0;
	new->next = act_cblock;
	rcblock = act_cblock = new;
}


/*
 * if the block is the last one, pop 'em.
 * (action when leaving a block).
 */

static void
close_cblock (block)
BLOCK *block; 
{
	CBLOCK *old;

#ifdef DEBUG
	if (do_debug)
		printf ("* closing current block.\n");
#endif /* DEBUG */

	if (! act_cblock)
		xabort ("INTERNAL: close_cblock: there is no block");

	if (act_cblock->block != block)
		xabort ("INTERNAL: close_cblock: not on curent block");
	
	old = act_cblock;
	rcblock = act_cblock = act_cblock->next;

	xfree ((char *) old);
}


/*
 * switch the act_act_cblock to the given. this is used to eval
 * something in a previous scope (especially: call_by_name).
 */

void
push_cblock (cb)
CBLOCK *cb;
{
	CBELM *new = TALLOC (CBELM);

	new->cblock = act_cblock;
	new->next = cbrelm;
	cbrelm = new;
	act_cblock = cb;
}

void
pop_cblock ()
{
	CBELM *old = cbrelm;
	cbrelm = old->next;
	act_cblock = old->cblock;
	xfree ((char *) old);
}


/*
 * push the valaddr of the last activation of the given symbol.
 * this is almost the left hand in an assignment.
 */

void
push_valaddr (source, lineno, sym, idx)
char *source;
int lineno;
SYMTAB *sym;
long idx;
{
	EVALELM *ev;
	ENUM type_tag type = sym->type;
	CBLOCK *cb;
	DATA *data;
	VALUE *val;

	if (type == ty_proc) {
		a60_error (source, lineno,
		   "illegal lefthand side in assignment (type is `%s')\n",
			   type_tag_name[type]);
		xabort ("runtime error");
	}

	if (TIS_FUNC(type))
		type = BASE_TYPE(type);

	for (cb = act_cblock; cb && cb->block != sym->block; cb = cb->next);

	if (!cb || ! cb->activ)
		xabort ("INTERNAL: push_valaddr: no activation!");

	data = (cb->activ)[sym->actidx].data;

	if (! data) {
		/*
		 * this is another one of the unexpected empty cell:
		 * (can be forced, skipping over declaration)
		 */
		a60_error (source, lineno, "uninitialized value\n");
		xabort ("runtime error");
	}

	ev = PUSH_EVALST(source, lineno, ev_valaddr);
	ev->u.valaddr.type = type;
	val = data->u.val;

	/* get `val + idx' element; bad hack for 16 bit integers: */
	while (idx > 30000) {
		val = val + 30000;
		idx = idx - 30000;
	}
	ev->u.valaddr.val = val + (int) idx;
}


/*
 * push the special; for label, proc, switch the symbol; for string
 * the char ptr.
 */

void
push_spec (source, lineno, sym)
char *source;
int lineno;
SYMTAB *sym;
{
	EVALELM *ev;

	if (TIS_PROC(sym->type)) {
		ev = PUSH_EVALST(source, lineno, ev_proc);
		ev->u.sym = sym;
	}
	else if (TIS_ARR(sym->type)) {
		ev = PUSH_EVALST(source, lineno, ev_sym);
		ev->u.sym = sym;
	}
	else if (sym->type == ty_label) {
		ev = PUSH_EVALST(source, lineno, ev_label);
		ev->u.sym = sym;
	}
	else if (sym->type == ty_switch) {
		ev = PUSH_EVALST(source, lineno, ev_switch);
		ev->u.sym = sym;
	}
	else {
		/* push it - no error. (why ?) */
		ev = PUSH_EVALST(source, lineno, ev_sym);
		ev->u.sym = sym;
	}
}


/*
 * what should a dummy do ?
 */

/* ARGSUSED */
void run_dummy (t)
TREE *t;
{
	if (trace)
		printf ("line %d: executing empty statement\n", t->lineno);

	return;
}


void
run_assign (t)
TREE *t;
{
	LHELM *lhelm;
	EVALELM *evp;
	int n = 0, got_a_type = 0;
	ENUM type_tag last_type;

	last_type = ty_unknown;
	lhelm = t->u.ass->lhelm;

 	while (lhelm) {
		do_push_lhelm (lhelm);
		evp = TOP_EVALST;
		if (evp->tag != ev_valaddr) {
			a60_error (lhelm->source, lhelm->lineno,
		   "illegal lefthand side (type is `%s')\n",
				   eval_tag_name[evp->tag]);
			xabort ("runtime error");
		}

		if (got_a_type
		    && BASE_TYPE(evp->u.valaddr.type) != last_type) {
			a60_error (lhelm->source, lhelm->lineno,
	   "multiple assignments only between equal types.\n");
			xabort ("runtime error");
		}
		got_a_type = 1;
		last_type = BASE_TYPE(evp->u.valaddr.type);

		lhelm = lhelm->next;
		n++;
	}

	do_eval_expr (t->u.ass->expr);
	DO_DEREF(t->u.ass->expr->source, t->u.ass->expr->lineno);

	while (n > 0) {

		if (trace) {
			evp = TOP_EVALST - 1;
			printf ("line %d: executing assign\n",
				evp->lineno);
		}

		assign_vals ( (n > 1) ? 1 : 0 );
		n--;
	}
}


/*
 * execute a goto statement:
 */

void 
run_goto (t)
TREE *t;
{
	SYMTAB *sym = (SYMTAB *) 0;
	EVALELM ev;

	if (trace)
		printf ("line %d: executing goto\n", t->lineno);

	do_eval_expr (t->u.dexpr);
	ev = * POP_EVALST;

	/*
	 * special: destination is an integer label:
	 */
	
	if (ev.tag == ev_ival) {
		SYMTAB *fnd;
		int nscop;
		char name [20];		/* should be enough for a long */

#ifdef DEBUG
		if (do_debug)
			printf ("** run_goto: goto to integer-label `%ld'\n",
				ev.u.ival);
#endif /* DEBUG */
		sprintf (name, "%ld", ev.u.ival);
		fnd = find_symbol_anywhere (name, act_cblock->block, &nscop);
		if (! fnd) {
			/*
			 * +++++++ warn at runtime.
			 */
#ifdef DEBUG
			if (do_debug)
				printf (
		"** run_goto: integer label not found (label `%s')\n", name);
#endif /* DEBUG */

			sym = (SYMTAB *) 0;	/* have a dummy goto */
		}
		else {
			sym = fnd;
		}
	}
	else if (ev.tag != ev_label) {
		a60_error (t->source, t->lineno,
	   "goto destination is not a label.\n");
		a60_error (t->source, t->lineno,
			   "(type is `%s')\n", eval_tag_name [ev.tag]);
		xabort ("runtime error");
	}
	else {
		sym = ev.u.sym;
	}

	/*
	 * if sym is null, the goto statement is like a dummy
	 * statement.
	 */

	if (! sym) {
#ifdef DEBUG
		if (do_debug)
			printf ("* dummy goto statement.\n");
#endif /* DEBUG */

		return;
	}

	/* clean up to the destination block: */

	while (sym->block != act_cblock->block) {
		leave_block (act_cblock->block);
		if (! act_cblock)
			xabort ("INTERNAL: run_goto: act_cblock is nil");
	}

	if (sym->type == ty_label)
		next_stmt = sym->u.fixval->u.stmt;
	else
		xabort ("INTERNAL: run_goto: switch ...");

	/* continue in the destination block: */
	longjmp (act_cblock->jmpbuf, 0);	
}


static ACT_BOUND *
run_bounds (bound, size)
BOUND *bound;
long *size;
{
	long lsize = 1, nsize;
	EVALELM ev;
	ACT_BOUND *newbound /** , *next ??? **/ ;

	if (! bound) {
		*size = lsize;
		return (ACT_BOUND *) 0;
	}

	newbound = TALLOC (ACT_BOUND);

	do_eval_expr (bound->low);
	DO_DEREF(bound->low->source, bound->low->lineno);
	ev = * POP_EVALST;
	if (ev.tag == ev_ival)
		newbound->from = ev.u.ival;
	else if (ev.tag == ev_rval)
		newbound->from = RVAL2IVAL(ev.u.rval);
	else {
		a60_error (bound->low->source, bound->low->lineno,
		   "array index must be of numerical type (found `%s')\n",
			   eval_tag_name[ev.tag]);
		xabort ("runtime error");
		/* never reached */
	}

	do_eval_expr (bound->high);
	DO_DEREF(bound->high->source, bound->high->lineno);
	ev = * POP_EVALST;
	if (ev.tag == ev_ival)
		newbound->til = ev.u.ival;
	else if (ev.tag == ev_rval)
		newbound->til = RVAL2IVAL(ev.u.rval);
	else {
		a60_error (bound->low->source, bound->low->lineno,
		   "array index must be of numerical type (found `%s')\n",
			   eval_tag_name[ev.tag]);
		xabort ("runtime error");
		/* never reached */
	}

	lsize = newbound->til - newbound->from + 1;
	if (lsize <= 0) {
		/****  ONK  ****/
		/*
		 * size <= 0 is ok ...
		 */

		a60_error (bound->low->source, bound->low->lineno,
			   "warning: size of array bound <= 0\n");
		lsize = 0;
	}

	newbound->next = run_bounds (bound->next, &nsize);

	newbound->mpl = nsize;
	*size = lsize * nsize;

	return newbound;
}


static char *
val_str (act, s)
ACTIV *act;
SYMTAB *s;
{
	DATA *data = act->data;
/***	SYMTAB *sym; ***/
	VALUE *val;
	long i;
	char *ptr;
	static long tmp_len = 0;
	static char *tmp;

	if (! s)
		return "<unknown value>";

	if (s->tag == s_byname) {
		return "<by_name parameter>";
	}

	if (! tmp_len) {
		tmp_len = 256;
		tmp = xmalloc (tmp_len);
	}

	switch (s->type) {
	case ty_label:
		sprintf (tmp, "stmt 0x%lx", (long) s->u.fixval->u.stmt);
		return tmp;
	case ty_switch:
		sprintf (tmp, "swit: ");
#if 0
		for(sym = s->u.fixval->u.symtab; sym; sym=sym->next)
			sprintf (tmp+strlen(tmp), " %s", sym->name);
#else
		/*******************/
#endif
		return tmp;
	case ty_integer:
		if (data->u.val->valid)
			sprintf (tmp, "%ld", data->u.val->u.ival);
		else
			sprintf (tmp, "--");
		return tmp;
		break;
	case ty_real:
		if (data->u.val->valid)
			sprintf (tmp, "%g", data->u.val->u.rval);
		else
			sprintf (tmp, "--");
		return tmp;
		break;
	case ty_bool:
		if (data->u.val->valid)
			sprintf (tmp, "%s", (data->u.val->u.ival)
				 ? "T" : "F");
		else
			sprintf (tmp, "--");
		return tmp;
		break;
	case ty_int_array:
		sprintf (tmp, "(%ld elms) ", act->arract->size);
		val = data->u.val;
		for (i=0; i<act->arract->size && i<100; i++, val++) {
			ptr = tmp + strlen(tmp);
			if (val->valid)
				sprintf (ptr, " %ld", val->u.ival);
			else
				sprintf (ptr, " --");

			if (strlen (tmp) > tmp_len-20) {
				tmp_len += 256;
				tmp = xrealloc (tmp, tmp_len);
			}
		}
		if (i < act->arract->size) {
			ptr = tmp + strlen(tmp);
			sprintf (ptr, " ...");
		}
		return tmp;
		break;
	case ty_real_array:
		*tmp = 0;
		val = data->u.val;
		for (i=0; i<act->arract->size && i<100; i++, val++) {
			ptr = tmp + strlen(tmp);
			if (val->valid)
				sprintf (ptr, " %g", val->u.rval);
			else
				sprintf (ptr, " --");

			if (strlen (tmp) > tmp_len-20) {
				tmp_len += 256;
				tmp = xrealloc (tmp, tmp_len);
			}
		}
		if (i < act->arract->size) {
			ptr = tmp + strlen(tmp);
			sprintf (ptr, " ...");
		}
		return tmp;
		break;
	case ty_bool_array:
		*tmp = 0;
		val = data->u.val;
		for (i=0; i<act->arract->size && i<100; i++, val++) {
			ptr = tmp + strlen(tmp);
			if (val->valid)
				sprintf (ptr, " %s", (val->u.ival)
					 ? "T" : "F");
			else
				sprintf (ptr, " --");

			if (strlen (tmp) > tmp_len-20) {
				tmp_len += 256;
				tmp = xrealloc (tmp, tmp_len);
			}
		}
		if (i < act->arract->size) {
			ptr = tmp + strlen(tmp);
			sprintf (ptr, " ...");
		}
		return tmp;
		break;
	case ty_proc:
	case ty_int_proc:
	case ty_real_proc:
	case ty_bool_proc:
		return "PROC";
		break;
	default:
		break;
	}
	return "???";
}


static void
print_one (sym, act)
SYMTAB *sym;
ACTIV *act;
{
	char *tmp;

	if (! sym) {
		printf ("  ???  unknown: ");
	}
	else {
		printf ("  %s %s: ", sym->name, type_tag_name[sym->type]);
	}

	tmp = val_str (act, sym);
	printf ("act: 0x%lx; data: 0x%lx; val: %s\n", (long) act,
		(long) act->data, tmp);
}

void
print_activ (cblock)
CBLOCK *cblock;
{
	SYMTAB *sym = cblock->block->symtab;
	ACTIV *act = cblock->activ;
	int i, nact = cblock->nact;

	printf ("---- activation: (block: 0x%lx)\n",
		(long) cblock->block);

	if (! nact)
		printf ("  <empty>\n");
	
	for (i=0; i<nact; i++) {
		print_one (sym, act);
		if (sym)
			sym = sym->next;
		act++;
	}
}


static void
activate_block (cblock)
CBLOCK *cblock;
{
	BLOCK *block = cblock->block;
	SYMTAB *sym;
	ACTIV *act;
	VALUE *val;
	DATA *new;
	ARRACT *arract;
	long i, size;

#ifdef DEBUG
	if (do_debug)
		printf ("** activating block:\n");
#endif /* DEBUG */

	if (! block->nact)
		return;

#ifdef DEBUG
	if (do_debug)
		printf ("** allocating %d activation structs.\n", block->nact);
#endif /* DEBUG */
	
	act = cblock->activ = NTALLOC(block->nact, ACTIV);
	cblock->nact = block->nact;

	for (sym=block->symtab; sym; sym=sym->next, act++) {

		act->sym = sym;

		/* allocate static dataspace only one time. */
		if (sym->own && sym->odata.data) {
			act->data = sym->odata.data;
			/* if arract is empty, it's ok */
			act->arract = sym->odata.arract;
			continue;
		}
		
		/* on proc-pseudo-block entry ignore param's. */
		if (SIS_PARM(sym->tag))
			continue;

		/* ignore labels / proc's. */
		if (sym->type == ty_label || sym->type == ty_proc)
			continue;
						
		if (TIS_BASET(sym->type) || TIS_FUNC(sym->type)) {
#ifdef DEBUG
			if (do_debug)
				printf ("** allocating simple space (%s).\n",
					sym->name);
#endif /* DEBUG */
			new = TALLOC (DATA);
 			new->u.val = TALLOC (VALUE);
 			new->u.val->valid = 0;
			act->data = new;
		}
		else if  (TIS_ARR(sym->type)) {
#ifdef DEBUG
			if (do_debug)
				printf ("** allocating array space (%s).\n",
					sym->name);
#endif /* DEBUG */
			new = TALLOC (DATA);
			arract = TALLOC (ARRACT);
			arract->act_bound = run_bounds (sym->u.arr->bound,
							&size);
			arract->size = size;
			act->arract = arract;
			new->u.val = NTALLOC(size, VALUE);
			for (val=new->u.val, i=0; i<size; i++, val++)
				val->valid = 0;
			act->data = new;
		}
		else if (sym->type == ty_switch) {
			/*
			 * eval the dexprs; assign them to the swiitch
			 * activation.
			 */
			int nelm = 0, i;
			EXPR *dex = sym->u.dexpr, *d;
			SWACT *swact = TALLOC (SWACT);
			EVALELM *ev;
			for (d=dex; d; nelm++, d=d->next);
			swact->nelm = nelm;
#ifdef DEBUG
			if (do_debug)
				printf ("** switch %s: %d elms.\n",
					sym->name, nelm);
#endif /* DEBUG */
			swact->targs = NTALLOC (nelm, SYMTAB *);
			for (i=0; i<nelm; i++) {
				do_eval_expr (dex);
				ev = POP_EVALST;
				if (ev->tag != ev_label) {
					a60_error (dex->source, dex->lineno,
			"bad element in switch list  (mindex %d)\n", i);
					xabort ("runtime error");
				}
				swact->targs [i] = ev->u.sym;
				dex = dex->next;
			}
			act->swact = swact;
#ifdef DEBUG
			if (do_debug)
				printf ("** switch initialized.\n");
#endif /* DEBUG */
		}
		else
			xabort ("INTERNAL: activate_block: bad type");

		if (sym->own && ! sym->odata.data) {
			sym->odata.data = act->data;
			sym->odata.arract = act->arract;
		}
	}

#ifdef DEBUG
	if (do_debug) {
		print_activ (act_cblock);
		printf ("* block is active.\n");
	}
#endif /* DEBUG */
}


static void
leave_block (block)
BLOCK *block;
{
	CBLOCK *cb = act_cblock;
	ACTIV *activ = cb->activ, *act;
	SYMTAB *sym = block->symtab;
	int i, nact = block->nact;

#ifdef DEBUG
	if (do_debug)
		printf ("** leaving block:\n");
#endif /* DEBUG */

	act = activ;
	for (i=0; i<nact; i++, sym=sym->next, act++) {

		if (! sym)
			xabort ("INTERNAL: leave_block: no symbol");

		/* skip unset activations */
		if (! act) {
			continue;
		}

		/* leave static dataspace untouched. */
		if (sym->own) {
			continue;
		}

		/* ignore labels / proc's. */
		if (sym->type == ty_label || sym->type == ty_proc) {
			continue;
		}

		if (act->arract && sym->tag != s_byvalue) {
			ACT_BOUND *ab = act->arract->act_bound, *ob;
#ifdef DEBUG
			if (do_debug)
				printf ("# freeing array bounds (%s)\n",
					sym->name);
#endif /* DEBUG */
			while (ab) {
				ob = ab; ab = ab->next;
				xfree ((char *) ob);
			}
#ifdef DEBUG
			if (do_debug)
				printf ("# freeing array (%s)\n",
					sym->name);
#endif /* DEBUG */
			xfree ((char *) (act->arract));
		}
		if (sym->tag != s_byname
		    && (TIS_ARR(sym->type) || TIS_FUNC (sym->type)
			|| TIS_BASET(sym->type))
		    && act->data) {
#ifdef DEBUG
			if (do_debug)
				printf ("# freeing value space (%s)\n",
					sym->name);
#endif /* DEBUG */
			xfree ((char *) (act->data->u.val));
		}
		if (act->data) {
#ifdef DEBUG
			if (do_debug)
				printf ("# freeing data space (%s)\n",
					sym->name);
#endif /* DEBUG */
			xfree ((char *) (act->data));
		}
	}

#ifdef DEBUG
	if (do_debug)
		printf ("* freeing activation space.\n");
#endif /* DEBUG */

	if (activ)
		xfree ((char *) activ);
	
	close_cblock (block);

#ifdef DEBUG
	if (do_debug)
		printf ("** block left.\n");
#endif /* DEBUG */
}


/*
 * work for the list of stmts; if ret_if_cont is set, return if
 * next stmt is continuation (used in if-then-else).
 */

static void
do_stmts (stmt, ret_if_cont)
TREE *stmt;
int ret_if_cont;
{
	while (stmt) {
		do_this (stmt);
		if (ret_if_cont && stmt->is_cont)
			return;
		stmt = stmt->next;
	}
}



void 
run_block (t)
TREE *t;
{
	open_cblock (t->u.block);
	/*
	 * may be, there is a goto in the activation phase; okay -
	 * make it  possible: 
	 */
	
	setjmp (act_cblock->jmpbuf);

	if (! act_cblock->activated) {
		act_cblock->activated = 1;
		activate_block (act_cblock);
		next_stmt = t->u.block->stmt;
	}
	
	do_stmts (next_stmt, 0);

#ifdef DEBUG
	if(do_debug)
		print_activ (act_cblock);
#endif /* DEBUG */

	leave_block (t->u.block);
}


/*
 * execute an if stmt.
 */

void run_ifstmt (t)
TREE *t;
{
	EVALELM *ev;
	EXPR *expr;

	if (trace)
		printf ("line %d: executing ifstmt\n", t->lineno);

	expr = t->u.ifstmt->cond;
	do_eval_expr (expr);
	DO_DEREF(expr->source, expr->lineno);

	ev = POP_EVALST;

	if (ev->tag != ev_bool)
		xabort ("INTERNAL: run_ifstmt: no bool");
	
	if (ev->u.bool)
		do_stmts (t->u.ifstmt->tthen, 1);
	else
		do_stmts (t->u.ifstmt->telse, 1);
}


/*
 * work for one for-element;
 */

static void
one_for_step (fstmt, felm)
FORSTMT *fstmt;
FORELM *felm;
{
	EVALELM ev, *evp;

	if (felm->tag == fe_expr) {
		do_eval_lhelm (fstmt->lvar);
		do_eval_expr (felm->expr[0]);
		DO_DEREF(felm->expr[0]->source, felm->expr[0]->lineno);
		assign_vals (0);
		felm = felm->next;
		do_stmts (fstmt->stmt, 0);
		return;
	}
	else if (felm->tag == fe_until) {
		/* initialisation: */
		do_eval_lhelm (fstmt->lvar);
		do_eval_expr (felm->expr[0]);
		DO_DEREF(felm->expr[0]->source, felm->expr[0]->lineno);
		assign_vals (0);
		/* loop: */
		for (;;) {
			/* calc: (v-c)*sign(b) */
			do_eval_lhelm (fstmt->lvar);
			DO_DEREF(fstmt->lvar->source, fstmt->lvar->lineno);
			do_eval_expr (felm->expr[2]);
			DO_DEREF(felm->expr[2]->source, felm->expr[2]->lineno);
			do_binop (e_op_minus);
			do_eval_expr (felm->expr[1]);
			DO_DEREF(felm->expr[1]->source, felm->expr[1]->lineno);
			do_eval_sign();
			do_binop (e_op_times);
			evp = PUSH_EVALST("??", 0, ev_ival);
			evp->u.ival = 0;
			do_binop (e_op_greater);
			ev = * POP_EVALST;
			if (ev.tag != ev_bool) {
				a60_error (ev.source, ev.lineno,
				   "condition must be of type boolean\n");
				xabort ("runtime error");
			}
			/* element exausted if true: */
			if (ev.u.bool) {
				return;
			}
			do_stmts (fstmt->stmt, 0);
			/* increment: */
			do_eval_lhelm (fstmt->lvar);
			do_eval_lhelm (fstmt->lvar);
			DO_DEREF(fstmt->lvar->source, fstmt->lvar->lineno);
			do_eval_expr (felm->expr[1]);
			DO_DEREF(felm->expr[1]->source, felm->expr[1]->lineno);
			do_binop (e_op_plus);
			assign_vals (0);
		}
	}
	else if (felm->tag == fe_while) {
		for (;;) {
			do_eval_lhelm (fstmt->lvar);
			do_eval_expr (felm->expr[0]);
			DO_DEREF(felm->expr[0]->source, felm->expr[0]->lineno);
			assign_vals (0);
			do_eval_expr (felm->expr[1]);
			DO_DEREF(felm->expr[1]->source, felm->expr[1]->lineno);
			ev = * POP_EVALST;
			if (ev.tag != ev_bool) {
				a60_error (ev.source, ev.lineno,
				   "condition must be of type boolean\n");
				xabort ("runtime error");
			}
			if (! ev.u.bool) {
				return;
			}
			do_stmts (fstmt->stmt, 0);
		}
	}
	else
		xabort ("INTERNAL: one_for_step: bad tag");
}


/*
 * execute a for stmt.
 */

void run_forstmt (t)
TREE *t;
{
	FORSTMT *fstmt = t->u.forstmt;
	FORELM *felm = fstmt->forelm;

	if (trace)
		printf ("line %d: executing for stmt\n", t->lineno);

	while (felm) {
		one_for_step (fstmt, felm);
		felm = felm->next;
	}
}



/*
 * push the parameters in reverse order onto the eval stack.
 */

static void
push_parameters (ex)
EXPR *ex;
{
	EVALELM *evp;

	if (ex) {
		push_parameters (ex->next);
		evp = PUSH_EVALST(ex->source, ex->lineno, ev_expr);
		evp->u.pexpr.expr = ex;
		evp->u.pexpr.cblock = act_cblock;
	}
}


void
exec_fcall (source, lineno, sym, fu)
char *source;
int lineno;
SYMTAB *sym;
FUNCALL *fu;
{
	ACTIV *act;
	SYMTAB *parm;
	EVALELM ev;
	TREE *stmt;
	int i, nparm;

	/* if sym is itself a parameter follow til real symbol: */
	while (sym->tag == s_byname) {
		DATA *data = get_sym_data (sym);
		push_spec_pexpr (&(data->u.pexpr));
		ev = * POP_EVALST;
		sym = ev.u.sym;
	}

	nparm = sym->u.pproc->nparm;

	/* nparm == -1 means varargs valid. */
	if (nparm != -1 && nparm != fu->nparm) {
		a60_error (source, lineno,
		   "number of actual parameters does not match formal\n");
		xabort ("runtime error");
	}

	nparm = fu->nparm;

	/*
	 * push all actual parameters on the value stack (as expr's).
	 */

	push_parameters (fu->parm);

#ifdef DEBUG
	if (do_debug)
		dump_evalst ("exec_fcall: after pushing parms");
#endif /* DEBUG */

	/*
	 * pop the parameters and assign them to a new activation
	 */

	open_cblock (sym->u.pproc->block);

#ifdef DEBUG
	if (do_debug)
		printf ("** allocating %d activation structs.\n", nparm);
#endif /* DEBUG */

	act = act_cblock->activ = NTALLOC(fu->nparm, ACTIV);
	act_cblock->nact = nparm;

	parm = sym->u.pproc->block->symtab;

	for (i=0; i<nparm; i++) {
		
		ev = * POP_EVALST;

		if (! parm || parm->tag == s_byname) {
			act->data = new_data ();
			act->data->u.pexpr = ev.u.pexpr;
		}
		else if (parm->tag == s_byvalue) {
			act->data = new_data ();
			do_eval_pexpr (&ev.u.pexpr);
			DO_DEREF(ev.source, ev.lineno);
			ev = * POP_EVALST;
			store_data (&ev, act, parm);
		}
		else
			xabort ("INTERNAL: run_proc: bad parm tag");

		if (parm)
			parm = parm->next;
		act++;
	}

#ifdef DEBUG
	if (do_debug)
		dump_evalst ("exec_fcall: after popping parms");
#endif /* DEBUG */

	stmt = sym->u.pproc->block->stmt;

	if (! stmt && sym->u.pproc->bltin) {
		(*sym->u.pproc->bltin) (sym, nparm);
	}
	else {
		do_stmts (stmt, 0);
	}

#ifdef DEBUG
	if (do_debug)
		print_activ (act_cblock);
#endif /* DEBUG */

	/* push return value onto stack : */
	if (TIS_FUNC(sym->type))
		push_valaddr ("???", 0, sym, (long) 0);

	leave_block (sym->u.pproc->block);

#ifdef DEBUG
	if (do_debug)
		printf ("# leave block done.\n");
#endif /* DEBUG */
}


DATA *
get_sym_data (sym)
SYMTAB *sym;
{
	CBLOCK *cb;
	DATA *data;

	cb = act_cblock;
	while (cb && cb->block != sym->block)
		cb = cb->next;

	if (!cb || ! cb->activ)
		xabort ("INTERNAL: get_sym_data: no activation!");

	data = (cb->activ)[sym->actidx].data;

	return data;
}


/*
 * return the switch activation for the given symbol:
 */

SWACT *
get_swact (sym)
SYMTAB *sym;
{
	CBLOCK *cb;
	SWACT *swact;

	cb = act_cblock;
	while (cb && cb->block != sym->block)
		cb = cb->next;

	if (!cb || ! cb->activ)
		xabort ("INTERNAL: get_swact: no activation!");

#ifdef DEBUG
	if (do_debug)
		printf ("** switch activation of %s: ", sym->name);
#endif /* DEBUG */
	swact = (cb->activ)[sym->actidx].swact;

#ifdef DEBUG
	if (do_debug)
		printf (" (actidx: %d)  0x%lx\n", sym->actidx, (long) swact);
#endif /* DEBUG */

	return swact;
}


/*
 * follow the byname expression til a symbol or a string value;
 */

void
push_spec_pexpr (pexpr)
PEXPR *pexpr;
{
	SYMTAB *sym;
	EVALELM *ev;
	EXPR *expr = pexpr->expr;

	if (pexpr->cblock)
		push_cblock (pexpr->cblock);
		
	if (EIS_SYMBOL(expr->tag) || expr->tag == e_fcall) {
		/*
		 * e_fcall is a proc symbol;
		 */
		if (expr->tag == e_fcall) {
			if (expr->u.lhelm->u.fcall->nparm) {

				a60_error (expr->source, expr->lineno,
			"procedure parameter must not have parameters\n");
				xabort ("runtime error");
			}
			sym = expr->u.lhelm->u.fcall->sym;
		}
		else
			sym = expr->u.lhelm->sym;

		/*****
		 * s_byname and ty_unknown: push_spec_pexpr or push_spec
		 * ???
		 ******/

		if (sym->tag == s_byname
		    && (TIS_SPECT(sym->type) || TIS_ARR(sym->type)
			|| sym->type == ty_unknown)) {
			DATA *data = get_sym_data (sym);
			push_spec_pexpr (&(data->u.pexpr));
		}
		else if (sym->tag == s_defined
			 && (TIS_SPECT(sym->type) || TIS_ARR(sym->type))) {
			push_spec (expr->source, expr->lineno, sym);
		}
		else if (sym->tag == s_defined && TIS_BASET(sym->type)) {
			push_spec (expr->source, expr->lineno, sym);
		}
		else {
			a60_error (expr->source, expr->lineno,
		"INTERNAL: push_spec_pexpr: sym is `%s'; type is `%s'\n",
				   sym->name, type_tag_name[sym->type]);
			xabort ("INTERNAL: push_spec_pexpr: what ???");
		}
	}
	else if (EIS_STRING(expr->tag)) {
		ev = PUSH_EVALST(expr->source, expr->lineno, ev_string);
		ev->u.string = expr->u.string;
	}
	else {
		/*
		 * hopefully correct to switch to do_eval-expr ...
		 */
#ifdef DEBUG
		if (do_debug)
			printf ("** pushing not a spec (expr tag is %s)\n", 
				expr_tag_name[expr->tag]);
#endif /* DEBUG */
		do_eval_expr (expr);
	}

	if (pexpr->cblock)
		pop_cblock ();
}


/*
 * execute an proc stmt.
 */
		
void
run_proc (t)
TREE *t;
{
	FUNCALL *fu = t->u.funcall;
	SYMTAB *sym = t->u.funcall->sym;
	EVALELM ev;

	if (trace)
		printf ("line %d: executing proc call (`%s')\n",
			t->lineno, sym->name);

	/* if sym is itself a parameter follow til real symbol: */
	while (TIS_PROC(sym->type) && sym->tag == s_byname) {
		DATA *data;
#ifdef DEBUG
		if (do_debug)
			printf ("** call with proc parm (%s):\n",
				sym->name);
#endif /* DEBUG */
		data = get_sym_data (sym);
		push_spec_pexpr (&(data->u.pexpr));
		ev = * POP_EVALST;
		sym = ev.u.sym;
#ifdef DEBUG
		if (do_debug)
			printf ("   -> now it is proc parm (%s).\n",
				sym->name);
#endif /* DEBUG */
	}

	exec_fcall (t->source, t->lineno, sym, fu);

	/* if a function returns pop the return value (valid or invalid) */
	if (TIS_FUNC(sym->type))
		(void) POP_EVALST;
}


void
assign_vals (push_back)
int push_back;
{
	EVALELM ev1, ev2;
	ENUM eval_tag t1;
	ENUM type_tag t2;
	VALADDR *va;


	ev1 = * POP_EVALST;		/* right hand side */
	ev2 = * POP_EVALST;		/* left hand side */

	if (! EV_PLAIN(ev1.tag)) {
		a60_error (ev1.source, ev1.lineno, 
		   "illegal righthand side in assignment (type is %s).\n",
			   eval_tag_name[ev1.tag]);
		xabort ("runtime error");
	}

	if (ev2.tag != ev_valaddr) {
		a60_error (ev2.source, ev2.lineno, 
		   "illegal lefthand side in assignment; (type is %s).\n",
			   eval_tag_name[ev2.tag]);
		xabort ("runtime error");
	}

	va = & ev2.u.valaddr;
	t1 = ev1.tag;
	t2 = BASE_TYPE(va->type);
	
#ifdef DEBUG
	if (do_debug)
		printf ("* assigning values:  %s :=  %s\n",
			type_tag_name[t2], eval_tag_name[t1]);
#endif /* DEBUG */

	if (t1 == ev_bool && t2 == ty_bool) {
		va->val->u.ival = ev1.u.bool;
		va->val->valid = 1;
	}
	else if (t1 == ev_ival && TIS_NUM(t2)) {
		if (t2 == ty_integer) {
			va->val->u.ival = ev1.u.ival;
			va->val->valid = 1;
		}
		else {
			va->val->u.rval = IVAL2RVAL(ev1.u.ival);
				va->val->valid = 1;
		}
	}
	else if (t1 == ev_rval && TIS_NUM(t2)) {
		if (t2 == ty_integer) {
			va->val->u.ival = RVAL2IVAL(ev1.u.rval);
			va->val->valid = 1;
		}
		else {
			va->val->u.rval = ev1.u.rval;
			va->val->valid = 1;
		}
	}
	else {
		a60_error (ev1.source, ev1.lineno,
			"illegal types in assignment (%s := %s)\n",
			type_tag_name[t2], eval_tag_name[t1]);
		xabort ("runtime error");
	}
	
#ifdef DEBUG
	if (do_debug) {
		printf ("** value copied; val is ");
		if (t2 == ty_integer)
			printf ("%ld\n", va->val->u.ival);
		else if (t2 == ty_real)
			printf ("%g\n", va->val->u.rval);
		else if (t2 == ty_bool)
			printf ("%s\n", (va->val->u.ival) ?
				"TRUE" : "FALSE");
		else
			printf ("BAD TYPE %d\n", (int) t2);
	}
#endif /* DEBUG */


	if (push_back) {
		/* push expression back: */

		(void) PUSH_EVALST(ev1.source, ev1.lineno, ev1.tag);
		* TOP_EVALST = ev1;
	}
}


static void
do_this (t)
TREE *t;
{
	if (! t) {
		xabort ("INTERNAL: do_this: nothing to do");
	}

	if (t->runme)
		(*t->runme)(t);
	else if (t->tag != t_label)  {
		a60_error (t->source, t->lineno,
			   "INTERNAL: no runme (tag %s) ?\n",
			   tree_tag_name[t->tag]);
	}
}


/*
 * do the realfun one time: interpret the root-tree.
 */

void
interpret ()
{
	if (verbose)
		fprintf (stderr, "starting execution:\n");

	if (! rtree)
		return;

	act_cblock = 0;

	do_this (rtree);
}

/* end of run.c */

