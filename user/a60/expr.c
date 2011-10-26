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
 * expr.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */


#include "comm.h"
#include "a60.h"
#include "util.h"
#include "tree.h"


char *expr_tag_name[] = {
	"nop",
	"symbol",		"string",
	"label",		"switch",
	"integer",
	"real",			"boolean",
	"function call",	"??fparm??",
	"negation",		"not",
	"plus",			"op_minus",
	"times",		"real division",
	"integer division",	"power",
	"and",			"op_or",
	"equiv",		"implication",
	"less",			"notgreater",
	"equal",		"notless",
	"greater",		"notequal",
	"conditional expression",
	"last_expr_tag_name"
};


EXPR *
new_expr (tag, type)
ENUM expr_tag tag;
ENUM type_tag type;
{
	EXPR *new = TALLOC (EXPR);
	new->tag = tag;
	new->type = type;
	new->next = 0;
	new->source = infname;
	new->lineno = lineno;

	return new;
}

EXPR *
new_mix_expr (e1, op, e2)
EXPR *e1;
ENUM expr_tag op;
EXPR *e2;
{
	EXPR *new;
	ENUM type_tag type;

	type = ty_unknown;

	new = new_expr (op, type);
	new->u.expr[0] = e1;
	new->u.expr[1] = e2;

	/* better to use the first arg, than parse end ...*/
	if (e1) {
		new->source = e1->source;
		new->lineno = e1->lineno;
	}

	return new;
}


/*
 * a new eswitch cell:
 */

ESWITCH *
new_eswitch (name, expr)
char *name;
EXPR *expr;
{
	ESWITCH *es = TALLOC (ESWITCH);
	SYMTAB *sym = new_symbol (name, ty_label, s_undef);

	es->sym = sym;
	es->expr = expr;

	return es;
}


/*
 * append one expression to the list of the other expressions;
 * (used for switch list)
 */

void
append_expr (e1, e2)
EXPR **e1, *e2;
{
	while (*e1)
		e1 = & (*e1)->next;

	*e1 = e2;
}


/*
 * print the expression to stdout:
 */

void print_expr (e)
EXPR *e;
{
	char *op = "";

	if (! e)
		return;

	printf (" (%s) ", type_tag_name[e->type]);

	if (e->tag == e_label) {
		printf ("%s (%s; block 0x%lx)", e->u.label->name,
			sym_tag_name[e->u.label->tag],
			(long) e->u.label->block);
		return;
	}

	if (e->tag == e_switch) {
		printf ("%s (%s; block 0x%lx) ",
			e->u.eswitch->sym->name,
			sym_tag_name[e->u.eswitch->sym->tag],
			(long) e->u.eswitch->sym->block);

		printf ("[ ");
		print_expr (e->u.eswitch->expr);
		printf (" ]");
		return;
	}
		


	if (e->tag == e_symbol) {
		printf ("%s (%s; block 0x%lx)", e->u.lhelm->sym->name,
			sym_tag_name[e->u.lhelm->sym->tag],
			(long) e->u.lhelm->sym->block);
		if (e->u.lhelm->mindex) {
			print_mindex (e->u.lhelm->mindex);
		}
		return;
	}

	if (e->tag == e_fcall) {
		EXPR *ex;

		printf ("%s (block 0x%lx) (",
			e->u.lhelm->sym->name,
			(long) e->u.lhelm->sym->block);

		for (ex=e->u.lhelm->u.fcall->parm; ex; ex=ex->next) {
			print_expr (ex);
			if (ex->next)
				printf (", ");
		}
		printf (") ");
		return;
	}


	if (e->tag == e_condexpr) {
		printf ("(");
		print_expr (e->u.expr[0]);
		printf (")  ?  ");
		print_expr (e->u.expr[1]);
		printf (" : ");
		print_expr (e->u.expr[2]);
		return;
	}

	switch (e->tag) {
	case e_nop: 
		printf ("nop"); 
		print_expr (e->u.expr[0]);
		break;
	case e_ival: printf ("%ld", e->u.ival); break;
	case e_rval: printf ("%g", e->u.rval); break;
	case e_bool: printf ("%s", (e->u.bool) ? "TRUE" : "FALSE"); break;
	case e_string: printf ("`%s'", e->u.string); break;
	case e_op_neg: op = "#-"; break;
	case e_op_plus:	op = "+"; break;
	case e_op_minus: op = "-"; break;
	case e_op_times: op = "*"; break;
	case e_op_rdiv: op = "/"; break;
	case e_op_idiv: op = "DIV"; break;
	case e_op_pow: op = "**"; break;
	case e_op_not: op = "#!"; break;
	case e_op_and: op = "&&"; break;
	case e_op_or: op = "||"; break;
	case e_op_equiv: op = "EQU"; break;
	case e_op_impl: op = "IMPL"; break;
	case e_op_less: op = "<"; break;
	case e_op_notgreater: op = "<="; break;
	case e_op_equal: op = "=="; break;
	case e_op_notless: op = ">="; break;
	case e_op_greater: op = ">"; break;
	case e_op_notequal: op = "!="; break;
	default:
		printf ("???");
	}
	
	if (*op) {
		if (*op == '#') {
			printf ("( %s (", op+1);
			print_expr (e->u.expr[0]); 
			printf ("))");
		}
		else {
			printf ("(");
			print_expr (e->u.expr[0]);
			printf (" %s ", op);
			print_expr (e->u.expr[1]);
			printf (")");
		}
	}
}


/*
 * new_mix_expr with check for unary minus.
 */

EXPR *
new_xmix_expr (e1, op, e2)
EXPR *e1;
ENUM expr_tag op;
EXPR *e2;
{
	EXPR *new;

	if (! unary_minus)
		return new_mix_expr (e1, op, e2);

	unary_minus = 0;
	new = new_mix_expr (e1, e_op_neg, (EXPR *) 0);
	
	return new_mix_expr (new, op, e2);
}

/* end of expr.c */
