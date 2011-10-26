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
 * stmt.c:					aug '90
 *
 * Erik Schoenfelder (schoenfr@ibr.cs.tu-bs.de)
 */

#include "comm.h"
#include "util.h"
#include "tree.h"
#include "run.h"


/*
 * conacatenate the two stmts; if is_cont is set, mark the next
 * element as continuation (used in if-then-else);
 */

void
append_stmt (t1, t2, is_cont)
TREE **t1, *t2;
int is_cont;
{
	TREE *last = (TREE *) 0;

	while (*t1) {
		last = *t1;
		t1 = &(*t1)->next;
	}

	*t1 = t2;

	if (is_cont) {
		if (! last)
			xabort ("INTERNAL: append_stmt: no last");
		last->is_cont = 1;
	}
}


/*
 * return new stmts. if-stmt, assign-stmt, goto-stmt.
 */

TREE *
new_if_stmt (expr)
EXPR *expr;
{
	TREE *new = new_tree (t_if_stmt);
	new->runme = run_ifstmt;
	new->u.ifstmt = TALLOC (IFSTMT);
	new->u.ifstmt->cond = expr;
	new->u.ifstmt->tthen = new->u.ifstmt->telse = (TREE *) 0;

	/* better to get the expr, than the 'then' clause... */
	new->lineno = expr->lineno;
	new->source = expr->source;

	return new;
}


TREE *
new_assign_stmt (lhelm, expr)
LHELM *lhelm;
EXPR *expr;
{
	TREE *new = new_tree (t_assign_stmt);
	new->runme = run_assign;
	new->u.ass = TALLOC (ASSIGN);
	new->u.ass->lhelm = lhelm;
	new->u.ass->expr = expr;

	return new;
}


TREE *
new_goto_stmt (expr)
EXPR *expr;
{
	TREE *new = new_tree (t_goto_stmt);
	new->runme = run_goto;
	new->u.dexpr = expr;
	return new;
}

/* end of stmt.c */
