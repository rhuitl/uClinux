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
 * check.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#include "comm.h"
#include "util.h"
#include "tree.h"
#include "a60.h"


/* count number of check errors. */
int cerrors = 0;

/* current block being checked. */
static BLOCK *cblock = 0;


/* forward: */
static int repl_sym ();
static void check_dexprs ();


/*
 * check the type of an unary expression.
 */

ENUM type_tag
check_unop_type (e)
EXPR *e;
{
	ENUM type_tag t = e->u.expr[0]->type;

	if (t == ty_unknown) {
		if (rwarn) {
			a60_error (e->source, e->lineno,
		   "warning: cannot check correct type conversion\n");
		}
		return ty_unknown;
	}
	
	if (t != ty_bool && e->tag == e_op_not) {
		a60_error (e->source, e->lineno,
			   "NOT only valid for bool-type\n");
		cerrors++;
		return ty_bool;
	}
	else if ((t != ty_integer && t != ty_real && e->tag == e_op_neg)
		 && e->tag == e_op_neg) {
		a60_error (e->source, e->lineno,
			   "negation only valid for integer or real type\n");
		cerrors++;
		return ty_real;
	}
	
	return t;
}


/*
 * check the type of a binary expression.
 */

ENUM type_tag
check_binop_type (e)
EXPR *e;
{
	ENUM type_tag t1, t2;

	t1 = e->u.expr[0]->type;
	t2 = e->u.expr[1]->type;

	if (t1 == ty_unknown || t2 == ty_unknown) {
		if (rwarn) {
			a60_error (e->source, e->lineno,
		   "warning: cannot check correct type conversion\n");
		}
		return ty_unknown;
	}

	if (e->tag == e_op_pow) {
		if (! TIS_NUM(t1) || ! TIS_NUM(t2)) {
			a60_error (e->source, e->lineno,
			   "POWER operands must be of integer or real type\n");
			cerrors++;
		}
		if (t1 == ty_integer && t2 == ty_integer)
			return ty_integer;
		else
			return ty_real;
	}
	else if (e->tag == e_op_rdiv) {
		if (! TIS_NUM(t1) || ! TIS_NUM(t2)) {
			a60_error (e->source, e->lineno,
			   "`/' operands must be of numerical type\n");
			cerrors++;
		}
		return ty_real;
	}
	else if (e->tag == e_op_idiv) {
		if (t1 != ty_integer || t2 != ty_integer) {
			a60_error (e->source, e->lineno,
				   "DIV operands must be of integer type\n");
			cerrors++;
		}
		return ty_integer;
	}
	else if (EIS_ARITHEXP(e->tag)) {
		if (! TIS_NUM(t1) || ! TIS_NUM(t2)) {
			a60_error (e->source, e->lineno,
		   "arithmetic operands must be of integer or real type\n");
			cerrors++;
		}
		if (t1 == ty_integer && t2 == ty_integer)
			return ty_integer;
		else
			return ty_real;
	}
	else if (EIS_RELEXP(e->tag)) {
		if (! TIS_NUM(t1) || ! TIS_NUM(t2)) {
			a60_error (e->source, e->lineno,
		   "relation operands must be of integer or real type\n");
			cerrors++;
		}
		return ty_bool;
	}
	else if (EIS_BOOLEXP(e->tag)) {
		if (t1 != ty_bool || t2 != ty_bool) {
			a60_error (e->source, e->lineno,
		   "logical operands must be of boolean type\n");
			cerrors++;
		}
		return ty_bool;
	}
	else {
		a60_error (e->source, e->lineno,
			   "INTERNAL: unhandled op: %d", e->tag);
		cerrors++;
	}
	return t1;
}


void
check_lhelm (source, lineno, lhelm)
char *source;
int lineno;
LHELM *lhelm;
{
	int dim = 0;

	if (lhelm->sym->tag == s_undef) {
		a60_error (source, lineno, "undef'd symbol `%s'\n",
			   lhelm->sym->name);
		cerrors++;
	}

	if (lhelm->mindex) {
		MINDEX *idx;

		for (idx=lhelm->mindex; idx; idx=idx->next) {
			check_expr (idx->expr);
			dim++;
		}

		/* still an array ? */
		if (lhelm->sym->type != ty_unknown &&
		    ! TIS_ARR (lhelm->sym->type)) {
			a60_error (source, lineno, "not an array `%s'\n",
				   lhelm->sym->name);
			cerrors++;
			return;
		}

		/* if an ordinary array, check the bounds: */
		if (lhelm->sym->tag == s_defined 
		    && dim != lhelm->sym->u.arr->dim) {
			a60_error (source, lineno,
		   "dimension of array does not match declaration\n");
			cerrors++;
		}
	}
}


/*
 * look for compatible types; (conversion passible ?)
 */

ENUM type_tag
check_conv_type (source, lineno, t1, t2)
char *source;
int lineno;
ENUM type_tag t1, t2;
{
	if (t1 == ty_unknown || t2 == ty_unknown) {
		if (rwarn) {
			a60_error (source, lineno,
		   "warning: cannot check correct type conversion\n");
		}
		return ty_unknown;
	}

	if (t1 == ty_bool) {
		if (t2 != t1) {
			a60_error (source, lineno,
			   "cannot convert between boolean type and %s\n", 
				   type_tag_name[t2]);
			cerrors++;
		}
		return ty_bool;
	}
	
	if (t1 == ty_real || t2 == ty_real) {
		if (! TIS_NUM(t1) || ! TIS_NUM(t2)) {
			a60_error (source, lineno, 
				   "cannot convert between %s type and %s\n",
				   type_tag_name[t1],
				   type_tag_name[t2]);
			cerrors++;
		}
		return ty_real;
	}

	if (t1 == ty_integer && t2 == ty_integer) {
		return ty_integer;
	}

	if (t1 == ty_string && t2 == ty_string) {
		return ty_string;
	}

	if (t1 == ty_label && t2 == ty_label) {
		return ty_label;
	}

	if (t1 == ty_switch && t2 == ty_switch) {
		return ty_switch;
	}

	a60_error (source, lineno, 
		   "cannot convert between %s type and %s\n",
		   type_tag_name[t1],
		   type_tag_name[t2]);
	cerrors++;
	return ty_real;
}


/*
 * check an expression; eval the type of the expression.
 */

void
check_expr (e)
EXPR *e;
{
	SYMTAB *sym;

	if (EIS_NUM(e->tag) || EIS_BOOL(e->tag) || EIS_STRING(e->tag))
		return;

	if (e->tag == e_fcall) {
		EXPR *ex;

		/* 
		 * if its a procedure call of a parameter proc, only
		 * check the return type.
		 */
		if (e->u.lhelm->sym->tag == s_byname) {
			if (e->u.lhelm->sym->type == ty_proc) {
				a60_error (e->source, e->lineno,
		   "must return a value (`%s')\n", e->u.lhelm->sym->name);
				cerrors++;
				return;
			}
			e->type = BASE_TYPE(e->u.lhelm->sym->type);
			return;
		}

		if (/* e->u.lhelm->sym->type != ty_unknown && */
		    ! TIS_FUNC (e->u.lhelm->sym->type)) {

			a60_error (e->source, e->lineno,
				   "not a function call `%s'.\n", 
				   e->u.lhelm->sym->name);
			cerrors++;
			return;
		}
		
		sym = e->u.lhelm->sym->u.pproc->block->symtab;
		for (ex=e->u.lhelm->u.fcall->parm; ex; ex=ex->next) {

			check_expr (ex);
			if (sym->tag == s_byname && ex->type != ty_unknown) {
				if (sym->type != ty_unknown
				    && ex->type != ty_unknown 
				    && sym->type != ex->type) {

					a60_error (e->source, e->lineno,
			   "actual parameter does not match formal (`%s')\n",
						   sym->name);
					cerrors++;
				}
			}
			sym = sym->next;
		}

		if (e->u.lhelm->sym->type == ty_proc) {
			a60_error (e->source, e->lineno,
				   "must return a value (`%s')\n",
				   e->u.lhelm->sym->name);
			cerrors++;
			e->type = ty_unknown;
		}
		else {
			e->type = TPROC_BASE(e->u.lhelm->sym->type);
		}			
	}
	else if (EIS_SYMBOL(e->tag)) {

		check_lhelm (e->source, e->lineno, e->u.lhelm);

		if (e->u.lhelm->sym->tag == s_undef) {
			/* error still reported */
		return;
		}

		/* look for call-by-name with unknown type: */
		if (e->u.lhelm->sym->tag == s_byname
		    && e->u.lhelm->sym->type == ty_unknown)
			return;

		/*
		 * if we gwt an mindex, choose the basetype, if not the
		 * given type.
		 */
		if (e->u.lhelm->mindex)
			e->type = BASE_TYPE(e->u.lhelm->sym->type);
		else
			e->type = e->u.lhelm->sym->type;
		if (! TIS_BASET(e->type) && ! TIS_SPECT(e->type)
		    && ! e->type == ty_string) {
			a60_error (e->source, e->lineno,
				   "INTERNAL: check_expr: illegal type!\n");
		}
	}
	else if (EIS_UNEXP(e->tag)) {
		check_expr (e->u.expr[0]);
		e->type = check_unop_type (e);
	}
	else if (EIS_BINEXP(e->tag)) {
		check_expr (e->u.expr[0]);
		check_expr (e->u.expr[1]);
		e->type = check_binop_type (e);
	}
	else if (e->tag == e_condexpr) {
#ifdef DEBUG
		if (do_debug)
			printf ("checking condexpr:...\n");
#endif /* DEBUG */
		check_expr (e->u.expr[0]);
		check_expr (e->u.expr[1]);
		check_expr (e->u.expr[2]);
		if (e->u.expr[0]->type != ty_bool) {
			if (e->u.expr[0]->type == ty_unknown) {
				if (rwarn)
					a60_error (e->source, e->lineno, 
		   "warning: cannot check correct conditional type\n");
			}
			else {
				a60_error (e->source, e->lineno, 
		   "conditional expression must be of type boolean\n");
				cerrors++;
			}
		}
		e->type = check_conv_type (e->source, e->lineno,
					   e->u.expr[1]->type,
					   e->u.expr[2]->type);
	}
	else if (EIS_NOP(e->tag)) {
		check_expr (e->u.expr[0]);
		e->type = e->u.expr[0]->type;
	}
	else if (e->tag == e_label) {
		check_dexprs (e);
		e->type = ty_label;
	}
	else if (e->tag == e_switch) {
		/* this is the runtime case:  foo [a + 2] */
		check_dexprs (e);
		/* so the resuklting type should be a label: */
		e->type = ty_label;
	}
	else {
		a60_error ("INTERNAL", 0,
			   "INTERNAL: check_expr: bad tag in expr (%d)",
			   e->tag);
		cerrors++;
	}
}


/*
 * check an designational expression; if the next ptr existes, check
 * the next element too.
 */

static void
check_dexprs (dexpr)
EXPR *dexpr;
{
	SYMTAB **sp = (SYMTAB **) 0, *s, *fnd;
	int nscop;

	if (dexpr->tag == e_condexpr) {
		check_expr (dexpr);
		if (dexpr->type != ty_label)
			xabort ("INTERNAL: check_dexprs: type not label");

		if (dexpr->next)
			check_dexprs (dexpr->next);
		return;
	}

	if (dexpr->tag == e_label) {
		sp = & dexpr->u.label;
	}
	else if (dexpr->tag == e_switch) {
		sp = & dexpr->u.eswitch->sym;
	}
	else
		xabort ("INTERNAL: check_dexprs: bad tag");

	/*
	 * relace the label, resp. the switch identifier:
	 */

#ifdef DEBUG
	if (do_debug)
		printf ("** check_dexpr: %s\n", (*sp)->name);
#endif /* DEBUG */
		
	s = *sp;

	if(s->tag == s_undef) {

#ifdef DEBUG
		if (do_debug)
			printf ("check: s_undef for %s; looking ...\n",
				s->name);
#endif /* DEBUG */

		fnd = find_symbol_anywhere (s->name, cblock, &nscop);
		/**** nscop ***/

		if (fnd && fnd->type != ty_switch
		    && fnd->type != ty_label
		    && fnd->type != ty_unknown) {
			a60_error (dexpr->source, dexpr->lineno, 
				   "invalid target for goto\n");
			cerrors++;
		}

		if (fnd) {
			xfree ((char *) (*sp));
			*sp= fnd;
		}
		else {
			a60_error (dexpr->source, dexpr->lineno,
				   "unknown symbol `%s'\n", s->name);
			cerrors++;
		}
	}	
	
	if (dexpr->next)
		check_dexprs (dexpr->next);
}


/*
 * check an goto stmt:
 */

static void
check_goto (t)
TREE *t;
{
	if (t->u.dexpr->tag == e_label || t->u.dexpr->tag == e_switch
	    || t->u.dexpr->tag == e_condexpr)
		check_dexprs (t->u.dexpr);
	else
		xabort ("INTERNAL: check_goto: bad tag");
}


/*
 * check a label; set symtab->u.fixval to the next stmt.
 */

static void
check_label (t)
TREE *t;
{
	SYMTAB *s = t->u.symbol;

	if (s->u.fixval) {
		a60_error (t->source, t->lineno,
			   "INTERNAL: check_label: fixval present!\n");
		cerrors++;
		return;
	}
	
	s->u.fixval = TALLOC (FIXVAL);
	s->u.fixval->u.stmt = t->next;
}


static int
repl_sym (s)
SYMTAB **s;
{
	SYMTAB *fnd;
	int nscop;

	fnd = find_symbol_anywhere ((*s)->name, cblock, &nscop);
	/**** nscop ****/

	if (fnd) {
		/*** free ??? ***/
		*s = fnd;
		return 1;
	}
	else
		return 0;
}


/* 
 * an assignment:
 */

static void
check_assign (t)
TREE *t;
{
	LHELM *l;
	ENUM type_tag last_type = ty_unknown;
	int got_a_type = 0;

	for (l=t->u.ass->lhelm; l; l=l->next) {
		check_lhelm (t->source, t->lineno, l);
		if (got_a_type && BASE_TYPE(l->sym->type) != last_type) {
			a60_error (t->source, t->lineno,
	   "multiple assignments only between equal types.\n");
			cerrors++;
		}

		if (l->sym->type != ty_unknown)
			got_a_type = 1;

		last_type = BASE_TYPE(l->sym->type);
	}
	check_expr (t->u.ass->expr);

	if (got_a_type) {
		if (last_type == ty_proc) {
			a60_error (t->source, t->lineno,
		   "assignment only valid for function designator\n");
			cerrors++;
		}
		else
			check_conv_type (t->source, t->lineno,
					 t->u.ass->expr->type, last_type);
	}
	else if (rwarn)
		a60_error (t->source, t->lineno,
	   "warning: cannot check type in assignment.\n");
}


/* 
 * check an if stmt:
 */

static void
check_ifstmt (t)
TREE *t;
{
	EXPR *cond = t->u.ifstmt->cond;

	check_expr (cond);

	if (cond->type != ty_bool) {
		if (cond->type == ty_unknown) {
			if (rwarn)
				a60_error (cond->source, cond->lineno, 
		   "warning: cannot check correct conditional type\n");
		}
		else {
			a60_error (cond->source, cond->lineno, 
		   "conditional expression must be of type boolean\n");
			cerrors++;
		}
	}

	/*
	 * check then and else part; append the continuation;
	 * this is magic for <if_clause> lab: <stmt>;
	 */

	check (t->u.ifstmt->tthen);
	append_stmt (&(t->u.ifstmt->tthen), t->next, 1);

	if (! t->u.ifstmt->telse)
		t->u.ifstmt->telse = new_tree (t_dummy_stmt);
	else
		check (t->u.ifstmt->telse);

	append_stmt (&(t->u.ifstmt->telse), t->next, 1);
}


static void
check_forstmt (t)
TREE *t;
{
	FORSTMT *fs = t->u.forstmt;
	FORELM *fe;

	for (fe=fs->forelm; fe; fe=fe->next) {
		if (fe->tag == fe_expr) {
			check_expr (fe->expr[0]);
		}
		else if (fe->tag == fe_until) {
			check_expr (fe->expr[0]);
			check_expr (fe->expr[1]);
			check_expr (fe->expr[2]);
		}
		else if (fe->tag == fe_while) {
			check_expr (fe->expr[0]);
			check_expr (fe->expr[1]);

			if (fe->expr[1]->type != ty_bool) {
				if (fe->expr[1]->type == ty_unknown) {
					if (rwarn)
						a60_error (fe->expr[1]->source,
							  fe->expr[1]->lineno, 
			   "warning: cannot check correct conditional type\n");
				}
				else {
					a60_error (fe->expr[1]->source,
						   fe->expr[1]->lineno, 
			   "conditional expression must be of type boolean\n");
					cerrors++;
				}
			}
		}
		else
			xabort ("INTRNAL: check: bad tag in forelm");
	}
	
	check  (fs->stmt);
}



/* 
 * check an procedure call.
 */

static void
check_proc (t)
TREE *t;
{
	EXPR *expr;
	int parm_proc, nparm;
	SYMTAB *parm;

	if (! repl_sym (&t->u.funcall->sym)) {
		a60_error (t->source, t->lineno, 
			   "unknown procedure `%s'\n",
			   t->u.funcall->sym->name);
		cerrors++;
		return;
	}

	/* is proc still a parameter ? */
	parm_proc = t->u.funcall->sym->tag == s_byname;

	/* check number of parameter; beware of parameter proc's */

	if (parm_proc) {
#ifdef DEBUG
		if (do_debug)
			printf ("** proc-call with formal parameter (%s)\n",
				t->u.funcall->sym->name);
#endif /* DEBUG */
		return;
	}

	nparm = t->u.funcall->sym->u.pproc->nparm;

	if (nparm == -1) {
		if (rwarn) {
			a60_error (t->source, t->lineno,
   "warning: cannot check parameter (proc with variable arguments)\n");
		}
		return;
	}


	if (t->u.funcall->nparm != t->u.funcall->sym->u.pproc->nparm) {
		a60_error (t->source, t->lineno,
		   "number of actual parameters does not match formal\n");
		cerrors++;
		return;
	}

	parm = t->u.funcall->sym->u.pproc->block->symtab;
	for (expr=t->u.funcall->parm; expr; expr=expr->next) {
		
		if (TIS_PROC(parm->type)) {

			if (expr->tag != e_fcall) {
				a60_error (expr->source, expr->lineno,
      "actual parameter does not match formal (must be a procedure).\n");
				cerrors++;
			}
			else if (expr->u.lhelm->u.fcall->nparm) {
				a60_error (expr->source, expr->lineno,
      "actual parameter does not match formal (must not have parameters).\n");
				cerrors++;
			}
			else 
				expr->type = e_fparm;
		}
		else if (parm->tag == s_byvalue) {
			check_expr (expr);

			(void) check_conv_type (expr->source, expr->lineno,
						BASE_TYPE(expr->type), 
						BASE_TYPE(parm->type));
		}
		else {
			if (rwarn) {
				a60_error (expr->source, expr->lineno,
      "warning: will check conversion at runtime (formal parm %s).\n",
					   parm->name);
			}
		}

		parm = parm->next;
	}
}


/*
 * look through the declarations; examine
 * proc-decls.
 */

void
check_decl (symtab)
SYMTAB *symtab;
{
	if (! symtab)
		return;
	
	if (TIS_PROC(symtab->type)) {
		cblock = symtab->u.pproc->block;
		check (symtab->u.pproc->block->stmt);
		cblock = symtab->u.pproc->block->up;
	}
	else if (symtab->type == ty_switch) {
		check_dexprs (symtab->u.dexpr);
	}

	check_decl (symtab->next);
}


/*
 * check this element.
 */

void
check (t)
TREE *t;
{
	if(! t)
		return;

	if (cverbose)
		fprintf (stderr, "checking: %s\n", tree_tag_name[t->tag]);

	switch (t->tag) {
		
	case t_block:
		cblock = t->u.block;
		check_decl (t->u.block->symtab);
		check (t->u.block->stmt);
		cblock = t->u.block->up;
		break;
	case t_dummy_stmt:
		break;
	case t_label:
		check_label (t);
		break;
	case t_goto_stmt:
		check_goto (t);
		break;
	case t_assign_stmt:
		check_assign (t);
		break;
	case t_if_stmt:
		check_ifstmt (t);
		break;
	case t_for_stmt:
		check_forstmt (t);
		break;
	case t_proc_stmt:
		check_proc (t);
		break;
	default:
		cerrors++;
		a60_error ("INTERNAL", 0, "INTERNAL: check: unknown tag %d\n",
			   t->tag);
	}

	check (t->next);
}

/*
 * second pass; climb along the tree and check for unknown symbols.
 * return 0 on success, anything else on success.
 */

int
check_tree ()
{

	TREE *tptr = rtree;

	cblock = 0;

	if(! tptr)
		return 0;
	
	while (tptr) {
		check (tptr);
		tptr = tptr->next;
	}
	
	return cerrors;
}

/* end of check.c */
