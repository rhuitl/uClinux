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
 * tree.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#include "comm.h"
#include "a60.h"
#include "util.h"
#include "tree.h"
#include "run.h"

/*
 * indent for code and for symtab.
 */
#define INDENT		4
#define SINDENT		6



char *
tree_tag_name[] = {
	"block",
	"label",
	"dummy stmt",
	"goto stmt",
	"assign stmt",
	"if stmt",
	"proc stmt",
	"for stmt",
	"last tree tag name"
};


/*
 * return a new tree element; lineno and source is set.
 */

TREE *
new_tree (tag)
ENUM tree_tag tag;
{
	TREE *new = TALLOC (TREE);
	new->source = infname;
	new->lineno = lineno;
	new->tag = tag;
	new->runme = run_dummy;
	new->next = (TREE *) 0;

	return new;
}


MINDEX *
new_mindex (e)
EXPR *e;
{
	MINDEX *new = TALLOC (MINDEX);

	new->expr = e;
	new->next = 0;

	return new;
}


LHELM *
new_lhelm (s)
SYMTAB *s;
{
	LHELM *new = TALLOC (LHELM);

	new->sym = s;
	new->mindex = 0;
	new->next = 0;

	new->source = infname;
	new->lineno = lineno;

	return new;
}


/*
 * make a new funcall struct.
 */

FUNCALL *
new_funcall (sym, parm)
SYMTAB *sym;
EXPR *parm;
{
	FUNCALL *new = TALLOC (FUNCALL);
	EXPR *ex;
	int n;

	for (n=0, ex=parm; ex; n++, ex=ex->next)
		continue;

	new->sym = sym;
	new->parm = parm;
	new->nparm = n;

	return new;
}


void
print_mindex (idx)
MINDEX *idx;
{
	printf ("[");
	for (; idx; idx=idx->next) {
		print_expr (idx->expr);
		if (idx->next)
			printf (",");
	}
	printf ("]");
}


void
print_indent (n)
int n;
{
	while (n-- > 0)
		printf (" ");
}



static void
print_assign (t)
TREE *t;
{
	LHELM *l;

	printf ("assign");
	
	for (l=t->u.ass->lhelm; l; l=l->next) {
		printf (" %s (block 0x%lx) ", l->sym->name,
			(long) (l->sym->block));
		if (l->mindex)
			print_mindex (l->mindex);
		printf (" := ");
	}
	print_expr (t->u.ass->expr);
	printf ("\n");
}


static void
print_indent_ifstmt (t, n)
TREE *t;
int n;
{
	printf ("if");
	print_expr (t->u.ifstmt->cond);
	printf ("\n");
	print_indent (n+2);
	printf ("then\n");
	print_indent_tree (t->u.ifstmt->tthen, 1, n+4);
	if (t->u.ifstmt->telse) {
		print_indent (n+2);
		printf ("else\n");
		print_indent_tree (t->u.ifstmt->telse, 1, n+4);
	}
}


static void
print_indent_forstmt (t, n)
TREE *t;
int n;
{
	FORSTMT *fs = t->u.forstmt;
	FORELM *fe;

	printf ("for");
	printf (" %s (%s) := ", fs->lvar->sym->name,
		type_tag_name[fs->lvar->sym->type]);
	
	for (fe=fs->forelm; fe; fe=fe->next) {
		if (fe->tag == fe_expr) {
			print_expr (fe->expr[0]);
		}
		else if (fe->tag == fe_until) {
			print_expr (fe->expr[0]);
			printf (" STEP ");
			print_expr (fe->expr[1]);
			printf (" UNTIL ");
			print_expr (fe->expr[2]);
		}
		else if (fe->tag == fe_while) {
			print_expr (fe->expr[0]);
			printf (" WHILE ");
			print_expr (fe->expr[1]);
		}
		else
			xabort ("INTRNAL: bad tag in forelm");
		
		if (fe->next)
			printf (", ");
	}
	
	printf (" DO\n");
	print_indent_tree (fs->stmt, 0, n+4);
}


static void
print_proc (t)
TREE *t;
{
	EXPR *ex;
	char *name = t->u.funcall->sym->name;

	if (! strcmp (name, "outstring"))
		name = "B_OUTSTR";
	else if (! strcmp (name, "outreal"))
		name = "B_OUTREAL";

	printf ("%s ( ", name);

	for (ex=t->u.funcall->parm; ex; ex=ex->next) {
		print_expr (ex);
		if (ex->next)
			printf (", ");
	}
	printf (" )\n");
}

/*
 * now an goto may be an label or swich-target;
 */

static void
print_goto (t)
TREE *t;
{
	printf ("goto ");
	print_expr (t->u.dexpr);
	printf ("\n");
}


void
print_indent_tree (t, ret_if_cont, n)
TREE *t;
int ret_if_cont, n;
{
	print_indent (n);

	if (! t) {
		printf("<end of list>\n");
		return;
	}

	switch (t->tag) {
	case t_block:
		printf("block: (0x%lx; up 0x%lx; ext_ref %d)\n",
		       (long) t->u.block, (long) t->u.block->up,
		       (int) t->u.block->ext_ref);
		/* skip builtin symbols ... */
		if (t->u.block->symtab)
#ifdef DEBUG
			if (do_debug || t->u.block->up)
				print_indent_symtab (t->u.block->symtab,
						     n+SINDENT);
#endif /* DEBUG */
		print_indent_tree (t->u.block->stmt, 0, n+INDENT);
		break;
	case t_dummy_stmt:
		printf ("dummy stmt\n");
		break;
	case t_goto_stmt:
		print_goto (t);
		break;
	case t_assign_stmt:
		print_assign (t);
		break;
	case t_if_stmt:
		print_indent_ifstmt (t, n);
		break;
	case t_label:
		printf ("%s:  (%s; sym 0x%lx; next 0x%lx)\n",
			(t->u.symbol) ?
			t->u.symbol->name : "!!unknown!!",
			(t->u.symbol) ?
			sym_tag_name[t->u.symbol->tag] : "???",
			(long) t->u.symbol,
			(long) t->next);
		break;
	case t_proc_stmt:
		print_proc (t);
		break;
	case t_for_stmt: 
		print_indent_forstmt (t, n);
		break;
	default:
		printf ("default: ??? (tag %d)\n", t->tag);
		break;
	}			
	
	if (ret_if_cont && t->is_cont) {
		print_indent (n);
		printf("<end of list>\n");
		return;
	}

	print_indent_tree (t->next, 0, n);
}

void
print_tree (t)
TREE *t;
{
	print_indent_tree (t, 0, 0);
	printf ("\n");
}

